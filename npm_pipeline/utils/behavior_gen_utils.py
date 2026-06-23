import copy
import json
import re
from dataclasses import dataclass, field

from loguru import logger

from base_classes.cpg_pdg_edge import Edge
from base_classes.pbg import PBG
from base_classes.pdg import PDG
from base_classes.pdg_node import PDGNode
from call_type_dict import FUNCTION_CALL, NORMAL_CALL, REQUIRE_CALL
from llm import llm_interpret_api_call_sequence
from npm_pipeline.classes.api_call import (
    CONFIDENCE_ADJACENCY,
    CONFIDENCE_BFS,
    CONFIDENCE_MODULE_ROOT,
    CONFIDENCE_REGISTRATION_ADJACENCY,
    CONFIDENCE_SHARED,
    APICall,
    APICallCollection,
    ResolvedAPICall,
)
from npm_pipeline.classes.call_graph_info import CallGraph, Function
from npm_pipeline.classes.code_Info import CodeInfo
from npm_pipeline.classes.dynamic_matching_record import ChainMatch
from npm_pipeline.classes.file_context import FileContext
from npm_pipeline.classes.identifier import Identifier
from npm_pipeline.classes.object import Object
from npm_pipeline.classes.package import AnalysisContext
from npm_pipeline.classes.serialized_types import (
    FileIORecord,
    SerializedAPIEntry,
    SerializedAPISequence,
)
from npm_pipeline.handlers.file_handler import (
    _READ_FILE_OPS,
    _WRITE_FILE_OPS,
    _is_binary_content,
    serialize_file_domain,
)
from npm_pipeline.handlers.subprocess_handler import process_subprocess_command
from npm_pipeline.processors.addition_processor import process_addition
from npm_pipeline.processors.assignment_plus_processor import process_assignment_plus
from npm_pipeline.processors.assignment_processor import process_assignment
from npm_pipeline.processors.await_processor import process_await_call
from npm_pipeline.processors.external_or_unresolved_call_processor import (
    process_external_or_unresolved_call,
)
from npm_pipeline.processors.field_access_processor import process_field_access
from npm_pipeline.processors.format_string_processor import process_format_string
from npm_pipeline.processors.identifier_processor import process_identifier_node
from npm_pipeline.processors.index_access_processor import process_index_access
from npm_pipeline.processors.iterator_processor import process_iterator
from npm_pipeline.processors.new_operation_processor import process_new_operation
from npm_pipeline.processors.require_processor import process_require
from npm_pipeline.utils.api_call_resolver import resolve_api_call
from npm_pipeline.utils.module_root_utils import normalize_for_prefix_match
from npm_pipeline.utils.parameter_utils import get_parameter_send_list
from npm_pipeline.utils.pdg_utils import (
    connect_ddg_by_param,
    edge_attr_contain_cfg,
    edge_attr_contain_ddg,
    find_pdg_by_method_full_name,
    get_pdg_of_callee,
    get_type_of_edge,
    merge_pbg,
    resolve_callee_via_call_expression,
)
from object_type_dict import PARAMETER, REST_PARAMETER
from sensitive_op import sensitive_call_finder

node_logger = logger.bind(node_trace=True)


def gen_behavior(
    filename: str,
    pdg: PDG,
    pdg_type: str,
    program_behavior: PBG,
    parameter_list: list | None,
    analysis_context: AnalysisContext,
    stage: str,
):
    """
    generate the behavior of the given pdg in [filename]
    :param filename: file of the pdg
    :param pdg: pdg
    :param pdg_type: the type of pdg, e.g. program, function
    :param program_behavior: the behavior of the program
    :param parameter_list: the parameter to the function
    :param analysis_context: the analysis context
    :param stage: the stage of the analysis
    :return: the behavior of the pdg
    """
    node_logger.info(
        f"↘️Start analyzing pdg. Name: {pdg.get_name()}, File: {filename}, pdg path: {pdg.pdg_path}"
    )
    analysis_context.file_in_cg.add(filename)
    nodes = pdg.get_nodes()

    # the first node is the entrance of the pdg
    first_node = nodes[pdg.get_first_node_id()]
    visited = analysis_context.global_visited
    program_behavior.add_pdg_node(first_node)
    program_behavior.set_entrance_node(first_node)
    out_edges = pdg.get_out_edges()
    if first_node.get_id() in out_edges:
        successive_node_ids = out_edges[first_node.get_id()]
        if pdg_type == "function" or pdg_type == "lambda":
            if first_node.get_id() in out_edges:
                process_function_parameters(
                    successive_node_ids=successive_node_ids,
                    pdg=pdg,
                    filename=filename,
                    parameter_list=parameter_list,
                    program_behavior=program_behavior,
                    analysis_context=analysis_context,
                )

    current_node = first_node
    behavior_gen_util(
        former_node=first_node,
        current_node=current_node,
        pdg=pdg,
        filename=filename,
        visited=visited,
        program_behavior=program_behavior,
        pdg_type=pdg_type,
        analysis_context=analysis_context,
        stage=stage,
    )
    node_logger.info(
        f"↗️Finish analyzing pdg. Name: {pdg.get_name()}, File: {filename}, pdg path: {pdg.pdg_path}"
    )
    return program_behavior


def behavior_gen_util(
    former_node: PDGNode,
    current_node: PDGNode,
    pdg: PDG,
    filename: str,
    visited: set,
    program_behavior: PBG,
    pdg_type: str,
    analysis_context: AnalysisContext,
    stage: str,
):
    """
    the behavior generation func for implicit main, function and anonymous function
    """
    in_edge = None
    if current_node != former_node:
        # not the first node
        in_edge = pdg.get_edges()[(former_node.get_id(), current_node.get_id())]
        program_behavior.add_pdg_edge(
            former_node.get_id(), current_node.get_id(), in_edge.get_attr()
        )
    if current_node.get_id() not in visited:
        # Determine whether the previous node is a branch.
        if (
            former_node.is_branch()
            and former_node.get_id() in analysis_context.program_context_backup
        ):
            program_context = copy.deepcopy(
                analysis_context.program_context_backup[former_node.get_id()]
            )
        program_behavior.add_pdg_node(current_node)
        visited.add(current_node.get_id())
        if current_node == former_node:
            pass
        elif current_node.get_node_type() == "RETURN":
            process_return_node(current_node, filename, pdg, program_behavior, analysis_context)
        elif current_node.get_node_type() == "METHOD_PARAMETER_IN":
            pass
        elif current_node.get_node_type() == "IDENTIFIER":
            process_identifier_node(
                current_node=current_node,
                pdg=pdg,
                filename=filename,
                program_behavior=program_behavior,
                analysis_context=analysis_context,
            )
        elif current_node.get_node_type() == "CALL":
            # `call type` node
            # the edge is not added before the call_node_process func
            call_node_process(
                former_node=former_node,
                current_node=current_node,
                pdg=pdg,
                filename=filename,
                program_behavior=program_behavior,
                in_edge=in_edge,
                analysis_context=analysis_context,
                stage=stage,
            )
        else:
            # other types
            pass

        out_edges = pdg.get_out_edges()
        if current_node.get_id() in out_edges:
            # judge current node contains branch
            _is_branch = is_branch(current_node, pdg)
            if _is_branch:
                # save the context
                current_node.set_the_branch()
                analysis_context.program_context_backup[current_node.get_id()] = copy.deepcopy(
                    program_context
                )

            successive_node_ids = out_edges[current_node.get_id()]
            node_id_list = []
            for successive_node_id in successive_node_ids:
                out_edge = pdg.get_edges()[(current_node.get_id(), successive_node_id)]

                # Determine connected edge types; prioritize CFG edges by placing them first.
                if edge_attr_contain_cfg(out_edge):
                    node_id_list.insert(0, ("CFG", successive_node_id))
                if edge_attr_contain_ddg(out_edge):
                    node_id_list.append(("DDG", successive_node_id))

            # Recursively call behavior_gen_util.
            for node_id in node_id_list:
                behavior_gen_util(
                    former_node=current_node,
                    current_node=pdg.get_nodes()[node_id[1]],
                    pdg=pdg,
                    filename=filename,
                    visited=visited,
                    program_behavior=program_behavior,
                    pdg_type=pdg_type,
                    analysis_context=analysis_context,
                    stage=stage,
                )
    else:
        # the node is already accessed
        if in_edge:
            type_of_in_edge = get_type_of_edge(in_edge)
            if type_of_in_edge == "DDG":
                # the former node has data dependency with current node
                if former_node.get_call_type() == "FUNCTION_CALL":
                    # the former node is function call, add the return value to the node
                    add_the_return_value_to_current_node(
                        former_node, current_node, in_edge, program_behavior
                    )


def call_node_process(
    former_node: PDGNode,
    current_node: PDGNode,
    pdg: PDG,
    filename: str,
    program_behavior: PBG,
    in_edge: Edge,
    analysis_context: AnalysisContext,
    stage: str,
):
    file_context = analysis_context.program_context.get_file_context(filename)
    call_name = current_node.get_name()
    if call_name == "__ecma.Array.factory":
        # array creation
        return
    if call_name == "<operator>.assignment":
        # the node is assignment
        process_assignment(
            current_node, pdg, filename, file_context, program_behavior, analysis_context
        )
    else:
        if former_node.get_call_type() == "FUNCTION_CALL":
            # the former node is function call but not in the assignment mode
            add_the_return_value_to_current_node(
                former_node, current_node, in_edge, program_behavior
            )
        if call_name == "<operator>.fieldAccess":
            process_field_access(
                current_node, pdg, file_context, program_behavior, analysis_context
            )
        elif call_name == "<operator>.indexAccess":
            process_index_access(
                current_node, pdg, file_context, program_behavior, analysis_context
            )
        elif call_name == "<operator>.new":
            process_new_operation(
                current_node, pdg, file_context, program_behavior, analysis_context, stage
            )
        elif call_name == "<operator>.iterator":
            process_iterator(current_node, pdg, file_context, program_behavior, analysis_context)
        elif call_name == "require":
            # process module require
            process_require(current_node, file_context, program_behavior, analysis_context, stage)
        elif call_name == "<operator>.addition":
            # A + B + C
            process_addition(current_node, pdg, program_behavior, analysis_context)
        elif call_name == "<operator>.assignmentPlus":
            process_assignment_plus(
                current_node, pdg, program_behavior, file_context, analysis_context
            )
        elif call_name == "<operator>.formatString":
            process_format_string(
                current_node, pdg, program_behavior, file_context, analysis_context
            )
        elif call_name == "<operator>.await":
            process_await_call(current_node, pdg, program_behavior, analysis_context)
        elif call_name is not None and re.search(r"<lambda>\d*", call_name):
            # Immediately invoked function.
            for callee_pdg in get_pdg_of_callee(current_node, analysis_context):
                IIFE_function(
                    current_node,
                    file_context,
                    callee_pdg,
                    program_behavior,
                    analysis_context,
                    stage,
                )

        # function or method call
        elif (
            call_name is not None
            and "<operator>" not in call_name
            and re.search(r"<lambda>\d*", call_name) is None
        ):
            resolve_and_process_call(
                current_node,
                pdg,
                call_name,
                file_context,
                program_behavior,
                analysis_context,
                stage,
            )
        elif call_name is None:
            resolve_and_process_call(
                current_node, pdg, "None", file_context, program_behavior, analysis_context, stage
            )
        else:
            pass


@dataclass
class _CallContext:
    """Per-call-site bundle of state passed to internal call-resolution helpers."""

    current_node: PDGNode
    pdg: PDG
    file_context: FileContext
    program_behavior: PBG
    analysis_context: AnalysisContext
    stage: str
    call_name: str
    parameters: list = field(default_factory=list)
    lambda_pdg: PDG | None = None

    @property
    def is_lambda(self) -> bool:
        return self.lambda_pdg is not None


def _resolve_lambda_pdg(
    parameters: list,
    analysis_context: AnalysisContext,
) -> PDG | None:
    """Resolve lambda PDG from the last parameter if it carries a <lambda> type."""
    if not (
        len(parameters) > 0
        and parameters[-1].get_value("TYPE_FULL_NAME")
        and "<lambda>" in parameters[-1].get_value("TYPE_FULL_NAME")
    ):
        return None
    method_full_name = parameters[-1].get_value("METHOD_FULL_NAME")
    if method_full_name:
        return find_pdg_by_method_full_name(
            method_full_name.strip(), analysis_context.current_code_info
        )
    return None


def _bind_large_file_contents(
    node: PDGNode,
    file_io_records: list[FileIORecord],
    resolved_sequence: list[ResolvedAPICall],
) -> None:
    """Bind large-text file content to the node."""

    targets: set[tuple[str, str]] = {
        (r.file_path, r.operation) for r in file_io_records if r.content_tier == "large_text"
    }
    if not targets:
        return

    for resolved in resolved_sequence:
        if resolved.domain != "File":
            continue
        qname = resolved.qualified_name
        if qname in _READ_FILE_OPS:
            operation = "read"
            fpath = (
                str(resolved.resolved_arguments)
                if resolved.resolved_arguments is not None
                else None
            )
            raw = resolved.resolved_return_value
        elif qname in _WRITE_FILE_OPS:
            operation = "write"
            if isinstance(resolved.resolved_arguments, dict):
                fpath = str(resolved.resolved_arguments.get("path", "")) or None
                raw = resolved.resolved_arguments.get("data")
            else:
                fpath = None
                raw = None
        else:
            continue

        if not fpath or (fpath, operation) not in targets:
            continue

        if raw is not None:
            content_str = str(raw)
            if not _is_binary_content(content_str):
                node.set_large_file_content(fpath, operation, content_str)


def _resolve_third_party_call_chain(
    current_node: PDGNode,
    callee: Function,
    analysis_context: AnalysisContext,
) -> None:
    """Phase A: locate third-party call chains for later batch processing.

    During the dynamic phase, API behavior chains are computed only in the following three cases:
      A. The node was not traversed during static analysis and is not in static_third_party_visited_nodes.
      B. The node was not identified as a third-party call during static analysis and is not in static_third_party_visited_nodes.
      C. The node was identified as a third-party call during static analysis but still needs further analysis and is in third_party_node.
    """
    node_id = current_node.get_id()
    if (
        node_id in analysis_context.static_third_party_visited_nodes
        and not analysis_context.is_static_pending_third_party(node_id)
    ):
        node_logger.debug(f"[Dynamic] Node {node_id}: skip call-chain resolution")
        return

    call_graph = analysis_context.current_code_info.call_graph
    api_call_info = analysis_context.current_code_info.api_call_info
    if not (call_graph and api_call_info):
        return

    bfs_matches = collect_bfs_matches(callee, call_graph, api_call_info)
    bfs_indices = [idx for idx, _ in bfs_matches]
    bfs_caller_keys = {APICallCollection.caller_key(call) for _, call in bfs_matches}

    # Pre-set the node's sensitive-ness in the same conditions as before
    # so downstream code that inspects the PDG before Phase B still sees
    # the right flag.  Whether the sequence ends up non-empty depends on
    # orphan recovery, but that does not change the "is this a sensitive
    # call site?" answer.
    if not analysis_context.is_static_pending_third_party(
        node_id
    ) and not analysis_context.is_static_pending_unresolved(node_id):
        current_node.set_sensitive_node(True)

    chain_root_file = getattr(callee, "file", None)

    chain = ChainMatch(
        node_id=node_id,
        node=current_node,
        chain_root_file=chain_root_file,
        bfs_caller_keys=bfs_caller_keys,
        bfs_indices=bfs_indices,
    )
    analysis_context.dynamic_matching_record.add_chain_match(chain)
    node_logger.debug(
        f"[Dynamic][PhaseA] chain node={node_id} root_file={chain_root_file} bfs={len(bfs_indices)}"
    )


def _resolve_third_party_in_dynamic(ctx: "_CallContext") -> bool:
    """In dynamic stage, detect require() calls and resolve third-party call chains."""
    current_node = ctx.current_node
    analysis_context = ctx.analysis_context

    # TODO: Attack chains inside require may be ignored.
    callees = get_callee_in_call_expression(current_node, analysis_context)
    node_modules_callees = [c for c in callees if "node_modules" in c.file]
    if not node_modules_callees:
        # Return immediately if no callee falls under node_modules.
        return False

    is_require_call = False
    if analysis_context.is_static_pending_unresolved(current_node.get_id()):
        # If the current node is unresolved.
        api_call = find_api_call_for_node(current_node, analysis_context.current_code_info)
        if api_call and api_call.module == "module" and api_call.function == "require":
            # If the current node is a require call.
            current_node.set_call_type(REQUIRE_CALL)
            is_require_call = True
            try:
                module_id = json.loads(api_call.arguments).get("id")
                if module_id:
                    current_node.set_require_call_dict(module_id)
            except json.JSONDecodeError:
                pass

    if is_require_call:
        return False

    for callee in node_modules_callees:
        _resolve_third_party_call_chain(current_node, callee, analysis_context)
    return True


def _log_call_site(ctx: "_CallContext") -> None:
    """Log the call-site we are about to analyze (matches the original logger.info)."""
    node = ctx.current_node
    node_logger.info(
        f"Call, id: {node.get_id()}, "
        f"Call name: {ctx.call_name}, "
        f"Line number: {node.get_line_number()}, File: {node.get_file_name()}\n"
        f"Code: {node.get_code()}"
    )


def _prepare_call_site(ctx: "_CallContext") -> None:
    """Initial bookkeeping before any callee resolution.

    Sets the default ``NORMAL_CALL`` call type, fetches Joern arguments,
    wires DDG-by-param edges, and pre-resolves a trailing-lambda PDG.
    All results downstream steps need are written onto ``ctx``.
    """
    ctx.current_node.set_call_type(NORMAL_CALL)

    ctx.parameters = ctx.analysis_context.current_code_info.cpg.get_argument_from_joern(
        ctx.current_node.get_id()
    )
    connect_ddg_by_param(
        ctx.current_node,
        ctx.parameters,
        ctx.file_context,
        ctx.program_behavior,
        ctx.pdg,
        ctx.analysis_context,
    )

    ctx.lambda_pdg = _resolve_lambda_pdg(ctx.parameters, ctx.analysis_context)


def _resolve_callee_pdgs(ctx: "_CallContext") -> list:
    """Run stage-aware callee PDG resolution.

    For ``dynamic`` stage we additionally try to detect third-party call
    chains and ``require()`` calls before falling back to the regular PDG
    lookup, matching the original ordering inside ``resolve_and_process_call``.
    Unknown stages now raise ``ValueError`` instead of being silently treated
    as an empty result, so misuse is surfaced eagerly.
    """
    if ctx.stage == "static":
        return get_pdg_of_callee(ctx.current_node, ctx.analysis_context)
    if ctx.stage == "dynamic":
        if _resolve_third_party_in_dynamic(ctx):
            return []
        # Use the dynamic call graph to resolve the callee PDG, covering package-internal calls
        # that static analysis could not resolve because call_expression_dict was missing.
        return get_pdg_of_callee(ctx.current_node, ctx.analysis_context)
    raise ValueError(f"Unknown stage: {ctx.stage!r}")


def _dispatch_resolved_callees(
    ctx: "_CallContext",
    function_pdgs: list,
) -> None:
    """Process every PDG resolved for the call site.

    Special case: when the trailing-lambda PDG is also one of the resolved
    function PDGs, we deliberately do **not** recurse into it via
    :func:`process_function_callee` here; instead the call is handed off to
    :func:`process_external_or_unresolved_call` (with ``is_lambda=True``) so
    that the lambda body is analyzed exactly once via the external path.
    Without this guard the same lambda PDG would be processed twice -- once
    as a "regular" callee in the loop below, and again as the trailing-lambda
    follow-up -- producing duplicated behavior nodes/edges.
    """
    if ctx.lambda_pdg is not None and ctx.lambda_pdg in function_pdgs:
        process_external_or_unresolved_call(
            ctx.current_node,
            ctx.pdg,
            ctx.file_context,
            ctx.program_behavior,
            ctx.parameters,
            True,
            ctx.lambda_pdg,
            ctx.call_name,
            ctx.analysis_context,
            ctx.stage,
        )
        return

    for fpdg in function_pdgs:
        function_behavior = process_function_callee(
            ctx.current_node,
            fpdg,
            ctx.file_context,
            ctx.pdg,
            ctx.program_behavior,
            ctx.analysis_context,
            stage=ctx.stage,
        )
        if function_behavior:
            ctx.current_node.set_call_type(FUNCTION_CALL)
            ctx.current_node.add_callee_pdg(fpdg)
            merge_pbg(ctx.program_behavior, function_behavior)
            ctx.current_node.set_behavior_of_call(function_behavior)

    if ctx.lambda_pdg is None:
        return

    lambda_behavior = process_function_callee(
        ctx.current_node,
        ctx.lambda_pdg,
        ctx.file_context,
        ctx.pdg,
        ctx.program_behavior,
        ctx.analysis_context,
        stage=ctx.stage,
    )
    if lambda_behavior:
        merge_pbg(ctx.program_behavior, lambda_behavior)


def _try_dynamic_unresolved(ctx: "_CallContext") -> bool:
    """Dynamic-only path when no callee PDG was resolved.

    Returns ``True`` iff a sensitive/known API match was found and the
    fallback should be skipped. ``handle_eval_call_in_dynamic`` is invoked
    purely for its side-effects (annotating eval invocations on the node)
    and is not allowed to short-circuit the fallback, mirroring the
    original behavior where its return value was ignored.
    """
    if handle_api_call_in_dynamic(
        ctx.current_node,
        ctx.pdg,
        ctx.call_name,
        ctx.file_context,
        ctx.program_behavior,
        ctx.is_lambda,
        ctx.lambda_pdg,
        ctx.analysis_context,
        ctx.stage,
    ):
        return True

    handle_eval_call_in_dynamic(ctx.current_node, ctx.analysis_context)
    return False


def _fallback_external_or_unresolved(ctx: "_CallContext") -> None:
    """Final fallback: treat the call as an external or unresolved invocation."""
    process_external_or_unresolved_call(
        ctx.current_node,
        ctx.pdg,
        ctx.file_context,
        ctx.program_behavior,
        ctx.parameters,
        ctx.is_lambda,
        ctx.lambda_pdg,
        ctx.call_name,
        ctx.analysis_context,
        ctx.stage,
    )


def resolve_and_process_call(
    current_node: PDGNode,
    pdg: PDG,
    call_name: str,
    file_context: FileContext,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
    stage: str,
):
    """Resolve the call and process it. *stage* is either ``"static"`` or ``"dynamic"``.

    The function follows a four-step pipeline:

    1. :func:`_prepare_call_site` -- default call type, parameters, DDG edges,
       and trailing-lambda PDG.
    2. :func:`_resolve_callee_pdgs` -- stage-aware lookup of callee PDGs
       (dynamic stage additionally handles third-party / require chains first).
    3. If any callee PDG was resolved, :func:`_dispatch_resolved_callees` runs
       each one (and the trailing lambda) and returns.
    4. Otherwise, in dynamic stage :func:`_try_dynamic_unresolved` may attach
       runtime API/eval information; if it finds a sensitive API match the
       call is fully handled and we return. Anything else falls through to
       :func:`_fallback_external_or_unresolved`.
    """
    ctx = _CallContext(
        current_node=current_node,
        pdg=pdg,
        file_context=file_context,
        program_behavior=program_behavior,
        analysis_context=analysis_context,
        stage=stage,
        call_name=call_name,
    )

    _log_call_site(ctx)
    _prepare_call_site(ctx)

    function_pdgs = _resolve_callee_pdgs(ctx)
    if function_pdgs:
        _dispatch_resolved_callees(ctx, function_pdgs)
        return

    if ctx.stage == "dynamic" and _try_dynamic_unresolved(ctx):
        return

    _fallback_external_or_unresolved(ctx)


def get_callee_in_call_expression(current_node: PDGNode, analysis_context: AnalysisContext) -> list:
    """
    get the callee(s) in the call expression dict.

    Returns ``list[Function]`` (empty list when not found). See
    ``resolve_callee_via_call_expression`` for details on how multiple
    candidate end-positions are disambiguated.
    """
    return resolve_callee_via_call_expression(current_node, analysis_context)


def process_function_parameters(
    successive_node_ids: list,
    pdg: PDG,
    filename: str,
    parameter_list: list | None,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    """
    Process function parameters and handle parameter passing.

    :param successive_node_ids: list of successive node IDs
    :param pdg: the PDG object
    :param filename: file name
    :param parameter_list: the parameter list to pass to the function
    :param program_behavior: the program behavior graph
    """
    is_rest = False
    parameter_send_index = 0
    for _index, successive_node_id in enumerate(successive_node_ids):
        successive_node = pdg.get_nodes()[successive_node_id]
        if successive_node.get_node_type() == "METHOD_PARAMETER_IN":
            # the node is parameter
            parameter_name = successive_node.get_name()
            parameter_code = successive_node.get_code()
            if parameter_name != "this":
                if parameter_code.startswith("..."):
                    is_rest = True
                    parameter = Identifier(
                        name=parameter_name,
                        line_number=successive_node.get_line_number(),
                        column_number=successive_node.get_column_number(),
                        node_id=successive_node.get_id(),
                        file=filename,
                        source_pdg=pdg.get_first_node_id(),
                        identifier_type=REST_PARAMETER,
                    )
                else:
                    parameter = Identifier(
                        name=parameter_name,
                        line_number=successive_node.get_line_number(),
                        column_number=successive_node.get_column_number(),
                        node_id=successive_node.get_id(),
                        source_pdg=pdg.get_first_node_id(),
                        file=filename,
                        identifier_type=PARAMETER,
                    )
                parameter_object = Object(
                    name=f"{parameter_name}-{successive_node.get_id()}",
                    object_type=PARAMETER,
                    source_pdg=pdg.get_first_node_id(),
                )
                parameter.set_ref_object(parameter_object)
                analysis_context.program_context.get_file_context(filename).add_identifier(
                    parameter
                )
                analysis_context.program_context.get_file_context(filename).add_object(
                    parameter_object
                )
                program_behavior.add_pdg_to_object_data_edge(
                    successive_node.get_id(), parameter_object
                )
                if parameter_list:
                    if is_rest:
                        # the rest parameter should be the last one
                        parameter.get_ref_object().set_qualified_name(None)
                        break
                    if 0 <= parameter_send_index < len(parameter_list):
                        send_parameter = parameter_list[parameter_send_index]
                    else:
                        send_parameter = None
                    if send_parameter is None:
                        parameter.get_ref_object().set_qualified_name(None)
                    elif isinstance(parameter_list[parameter_send_index], Object):
                        parameter.set_ref_object(parameter_list[parameter_send_index])
                        program_behavior.add_object_to_pdg_edge(
                            parameter_list[parameter_send_index],
                            successive_node.get_id(),
                        )
                    elif isinstance(parameter_list[parameter_send_index], tuple):
                        base_object = parameter_list[parameter_send_index][0]
                        property_list = list(parameter_list[parameter_send_index][1])
                        actual_value = base_object.get_property_actual_value(property_list)
                        if isinstance(actual_value, Object):
                            # Points to Object.
                            parameter.set_ref_object(actual_value)
                            program_behavior.add_object_to_pdg_edge(
                                actual_value, successive_node.get_id()
                            )
                        else:
                            parameter.get_ref_object().set_qualified_name(actual_value)
                        pass
                    else:
                        parameter.get_ref_object().set_qualified_name(None)
                    parameter_send_index += 1


def process_function_callee(
    current_node: PDGNode,
    function_pdg: PDG,
    file_context: FileContext,
    pdg: PDG,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
    stage: str,
    is_lambda=False,
):
    if file_context.function_in_stack(f"{function_pdg.get_full_name()}"):
        node_logger.info(f"{function_pdg.get_name()} is in loop")
        return None
    file_context.add_stack(f"{function_pdg.get_full_name().strip()}")
    analysis_context.current_code_info.pdg_analyzed[function_pdg.get_first_node_id()] = True

    # Get the first node of the function call.
    function_call_entrance_id = function_pdg.get_first_node_id()

    # The connector edge type is DDG.
    program_behavior.add_pdg_edge(current_node.get_id(), function_call_entrance_id, ["DDG", "CFG"])

    new_program_behavior = PBG(
        analysis_context.current_code_info.cpg,
        analysis_context.current_code_info.pdg_dict,
        analysis_context.current_code_info.formatted_package_dir,
        analysis_context.package_name,
    )
    if not is_lambda:
        # get the argument list by Joern
        parameter_list = analysis_context.current_code_info.cpg.get_argument_from_joern(
            current_node.get_id()
        )
        parameter_send_list = get_parameter_send_list(
            parameter_list, current_node, file_context, pdg
        )

        function_call_result = gen_behavior(
            function_pdg.get_file_name(),
            function_pdg,
            "function",
            new_program_behavior,
            parameter_list=parameter_send_list,
            analysis_context=analysis_context,
            stage=stage,
        )
    else:
        function_call_result = gen_behavior(
            function_pdg.get_file_name(),
            function_pdg,
            "function",
            new_program_behavior,
            parameter_list=None,
            analysis_context=analysis_context,
            stage=stage,
        )
    file_context.delete_last_stack()
    return function_call_result


def handle_api_call_in_dynamic(
    current_node: PDGNode,
    pdg: PDG,
    call_name: str,
    file_context: FileContext,
    program_behavior: PBG,
    is_lambda: bool,
    lambda_pdg: PDGNode | None,
    analysis_context: AnalysisContext,
    stage: str,
) -> bool:
    """
    Process API call information. Return True when processing succeeds.
    """
    api_call = find_api_call_for_node(current_node, analysis_context.current_code_info)
    if api_call is None:
        return False

    api_call_full_name = f"{api_call.module}.{api_call.function}"
    sensitive_call = sensitive_call_finder.query(api_call_full_name)
    if sensitive_call:
        current_node.set_sensitive_node(True)
        current_node.set_sensitive_dict(sensitive_call, call_name)
        node_logger.debug(
            f"[Sensitive Call] code: {current_node.get_code().strip()}, qualified name: {sensitive_call['qualified_name']}"
        )

        resolved = resolve_api_call(api_call, sensitive_call)
        current_node.set_resolved_api_call(resolved)

        # Phase A: record this single call match so Phase B's global
        # orphan recovery knows this runtime entry is already claimed by
        # a sensitive-API node and shouldn't be re-attributed.
        analysis_context.dynamic_matching_record.add_single_match(
            node_id=current_node.get_id(),
            caller_key=APICallCollection.caller_key(api_call),
        )

        if sensitive_call["domain"] == "Process" and resolved.resolved_arguments:
            process_subprocess_command(
                current_node,
                program_behavior,
                sensitive_call["qualified_name"],
                resolved.resolved_arguments,
                analysis_context,
                stage,
            )

        assign_qualified_path(api_call_full_name, current_node, file_context)

    if is_lambda:
        lambda_behavior = process_function_callee(
            current_node,
            lambda_pdg,
            file_context,
            pdg,
            program_behavior,
            analysis_context,
            stage,
            is_lambda=True,
        )
        if lambda_behavior:
            merge_pbg(program_behavior, lambda_behavior)
            current_node.set_behavior_of_call(lambda_behavior)


def handle_eval_call_in_dynamic(
    current_node: PDGNode,
    analysis_context: AnalysisContext,
) -> bool:
    """Backfill eval call information collected during dynamic analysis onto PDG nodes."""
    matches = find_eval_calls_for_node(current_node, analysis_context.current_code_info)
    if not matches:
        return False

    seen_args: set[str] = set()
    unique_args: list[str] = []
    for entry in matches:
        arg = entry.get("arg")
        if not isinstance(arg, str):
            continue
        if arg in seen_args:
            continue
        seen_args.add(arg)
        unique_args.append(arg)

    current_node.set_eval_call_dict(
        {
            "args": unique_args,
            "invocation_count": len(matches),
        }
    )
    node_logger.debug(
        f"[Dynamic Eval] node id: {current_node.get_id()}, "
        f"invocations: {len(matches)}, unique args: {len(unique_args)}"
    )
    return True


def process_return_node(
    current_node: PDGNode,
    filename: str,
    pdg: PDG,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
):
    # return object of the function
    program_behavior.add_return_node(current_node)
    current_node.set_is_return(True)
    ast = analysis_context.current_code_info.cpg.get_children_ast(current_node.get_id())
    if len(ast) == 0:
        logger.info(
            f"The AST children size is zero in return node. Node id: {current_node.get_id()}"
        )
    else:
        first_return_value = ast[0]
        first_return_value_pdg_node = (
            pdg.get_node(first_return_value.get_id())
            if first_return_value.get_id() in pdg.get_nodes()
            else None
        )
        if first_return_value_pdg_node:
            if first_return_value_pdg_node.get_node_type() == "IDENTIFIER":
                found_identifier = analysis_context.program_context.get_file_context(
                    filename
                ).find_identifier(
                    first_return_value_pdg_node.get_code(), current_node.get_line_number()
                )
                if found_identifier:
                    current_node.set_return_value(found_identifier.get_ref_object())
                    ref_object = found_identifier.get_ref_object()
                    program_behavior.add_object_to_pdg_edge(ref_object, current_node.get_id())
            else:
                current_node.set_return_value(first_return_value_pdg_node.get_qualified_path())
            program_behavior.add_pdg_edge(
                first_return_value_pdg_node.get_id(), current_node.get_id(), ["DDG"]
            )


def is_branch(pdg_node: PDGNode, pdg: PDG):
    current_node_id = pdg_node.get_id()
    successive_node_ids = pdg.get_out_edges()[current_node_id]
    branch_size = 0
    for successive_node_id in successive_node_ids:
        out_edge = pdg.get_edges()[(current_node_id, successive_node_id)]
        if edge_attr_contain_cfg(out_edge) == "CFG":
            branch_size += 1
    if branch_size > 2:
        return True
    else:
        return False


def add_the_return_value_to_current_node(
    former_node: PDGNode, current_node: PDGNode, in_edge: Edge, program_behavior: PBG
):
    """
    the former node is function call, which have return value
    """
    function_behavior = former_node.get_behavior_of_call()
    if function_behavior:
        return_value_list = function_behavior.get_return_value()
        if return_value_list and len(return_value_list) > 0:
            # exist return value
            type_of_in_edge = get_type_of_edge(in_edge)
            if type_of_in_edge == "DDG":
                attr_list = in_edge.get_attr()
            else:
                attr_list = ["DDG"]
            for return_value in return_value_list:
                program_behavior.add_pdg_edge(
                    return_value.get_id(), current_node.get_id(), attr_list
                )


def IIFE_function(
    current_node: PDGNode,
    depth_tree: FileContext,
    lambda_pdg: PDG,
    program_behavior: PBG,
    analysis_context: AnalysisContext,
    stage: str,
):
    """
    Trigger the IIFE function
    """
    analysis_context.current_code_info.pdg_analyzed[lambda_pdg.get_first_node_id()] = True
    depth_tree.add_stack(lambda_pdg.get_full_name().strip())

    # using the ddg to connect the lambda function to the caller
    program_behavior.add_pdg_edge(
        current_node.get_id(), lambda_pdg.get_first_node_id(), ["DDG", "CFG"]
    )
    new_program_behavior = PBG(
        analysis_context.current_code_info.cpg,
        analysis_context.current_code_info.pdg_dict,
        analysis_context.current_code_info.formatted_package_dir,
        analysis_context.package_name,
    )
    anonymous_call_result = gen_behavior(
        current_node.get_file_name(),
        lambda_pdg,
        "lambda",
        new_program_behavior,
        parameter_list=None,
        analysis_context=analysis_context,
        stage=stage,
    )
    depth_tree.delete_last_stack()
    merge_pbg(program_behavior, anonymous_call_result)


def remove_some_pdg_edge(current_node: PDGNode, pdg: PDG, current_code_info: CodeInfo):
    # remove useless pdg edge
    top_argument = current_code_info.cpg.get_argument_from_joern_index_less_than_one(
        current_node.get_id()
    )
    arg_name_list = []
    for arg in top_argument:
        arg_name_list.append(f"DDG: {arg.get_value('NAME')}")
    out_edges = pdg.get_out_edges()
    current_node_out_edges = out_edges.get(current_node.get_id(), [])
    for edge_id in current_node_out_edges:
        edge = pdg.get_edges()[(current_node.get_id(), edge_id)]
        attr_list = edge.get_attr()
        for i, attr in enumerate(attr_list):
            if attr in arg_name_list:
                attr_list[i] = attr.replace("DDG: ", "REMOVE: ", 1)
        # Update the edge's attributes with the modified list
        edge.change_attr(attr_list)


def calculate_end_position(code_snippet: str, start_line: int, start_column: int):
    lines = code_snippet.splitlines()
    if not lines:
        return start_line, start_column
    if len(lines) == 1:
        end_line = start_line
        end_column = start_column + len(lines[0])
    else:
        end_line = start_line + len(lines) - 1
        end_column = len(lines[-1])
    return end_line, end_column


def find_api_call_for_node(current_node: PDGNode, code_info: CodeInfo) -> APICall | None:
    """
    Locate the matching API call record in api_call_info using the PDG node code location.
    """
    code = current_node.get_code().strip()
    end_line, end_column = calculate_end_position(
        code, current_node.get_line_number(), current_node.get_column_number()
    )
    return code_info.api_call_info.find_api_call(
        "function",
        current_node.get_file_name(),
        current_node.get_line_number() - 1,
        current_node.get_column_number(),
        end_line - 1,
        end_column,
    )


def find_eval_calls_for_node(current_node: PDGNode, code_info: CodeInfo) -> list[dict]:
    """Match the corresponding eval call from eval_call_info collected during dynamic analysis using the PDG node code location."""
    eval_call_info = getattr(code_info, "eval_call_info", None)
    if not eval_call_info:
        return []

    node_file = current_node.get_file_name()
    if node_file is None:
        return []
    node_file_norm = normalize_for_prefix_match(node_file)

    node_start_line = current_node.get_line_number()
    if node_start_line is None or current_node.get_column_number() is None:
        return []
    node_start_column = current_node.get_column_number() + 1  # 0-based -> 1-based

    matches: list[dict] = []
    for file_key, entries in eval_call_info.items():
        if normalize_for_prefix_match(file_key) != node_file_norm:
            continue
        for entry in entries:
            if (
                entry.get("start_line") == node_start_line
                and entry.get("start_column") == node_start_column
            ):
                matches.append(entry)
    return matches


def collect_bfs_matches(
    callee: Function,
    call_graph: CallGraph,
    api_call_info: APICallCollection,
) -> list[tuple[int, APICall]]:
    """
    Phase-A primitive: BFS over ``fun2fun`` edges reachable from *callee*
    and collect every API call whose caller position falls inside one of
    those functions.
    """
    transitive_callees = call_graph.get_transitive_callees(callee)

    collected: list[tuple[int, APICall]] = []
    seen: set[tuple] = set()
    for func in transitive_callees:
        matched = api_call_info.find_api_calls_in_function_with_indices(
            func.file,
            func.start_line,
            func.start_column,
            func.end_line,
            func.end_column,
        )
        for idx, api_call in matched:
            key = APICallCollection.caller_key(api_call)
            if key in seen:
                continue
            seen.add(key)
            collected.append((idx, api_call))

    collected.sort(key=lambda p: p[0])
    return collected


def assign_qualified_path(
    api_qualified_name: str, current_node: PDGNode, file_context: FileContext
):
    split_res = api_qualified_name.split(".")
    module_name = split_res[0]
    if module_name == "global":
        global_object = file_context.find_global_object(split_res[1])
        if global_object:
            current_node.set_qualified_path((global_object, []))
    else:
        if module_name == "Buffer":
            ref_object = file_context.find_global_object("Buffer")
        else:
            ref_object = file_context.get_core_module_object(module_name)
        if ref_object:
            current_node.set_qualified_path((ref_object, split_res[1:]))


def generate_behavior_description_from_sequence(
    sequence: list[ResolvedAPICall], node_id: int | None = None
) -> dict | None:
    """Serialize the API sequence and call the LLM to get a behavior description plus key files."""

    serialized = serialize_api_sequence(sequence)
    file_io_records = serialized.file_io_records
    result = llm_interpret_api_call_sequence(serialized.to_llm_dict())
    if result and "behavior_description" in result:
        # bind the node_id to the file_io_records
        if node_id is not None:
            for rec in file_io_records:
                rec.node_id = node_id

        large_text_keys: set[tuple[str, str]] = {
            (r.file_path, r.operation) for r in file_io_records
        }
        behavior_text = result.get("behavior_description", "")
        filtered_key_files: list[dict] = []
        for kf in result.get("key_files", []):
            fp = kf.get("file_path", "")
            op = kf.get("operation", "")
            if (fp, op) in large_text_keys and fp in behavior_text:
                if node_id is not None:
                    kf["node_id"] = node_id
                filtered_key_files.append(kf)

        result["key_files"] = filtered_key_files
        result["file_io_records"] = file_io_records
        return result
    return None


def serialize_api_sequence(sequence: list[ResolvedAPICall]) -> SerializedAPISequence:
    """Build a compact, JSON-friendly representation of an API call sequence
    suitable for sending to the LLM.

    The returned :class:`SerializedAPISequence` bundles the entry list with
    sidecar ``FileIORecord`` instances for large-text file operations.
    """
    result = SerializedAPISequence()

    for resolved in sequence:
        domain = resolved.domain
        category = (
            resolved.sensitive_info.get("behavior", domain) if resolved.sensitive_info else domain
        )

        if domain == "File":
            entry = serialize_file_domain(resolved, category)
            _collect_file_io_record(entry, resolved, result.file_io_records)
        else:
            entry = SerializedAPIEntry(
                qualified_name=resolved.qualified_name,
                domain=domain,
                category=category,
                arguments=resolved.resolved_arguments,
            )
        # Propagate provenance tag from the resolved call to its serialized
        # form so the LLM / downstream consumers know how much to trust the
        # attribution.
        entry.confidence = getattr(resolved, "confidence", CONFIDENCE_BFS) or CONFIDENCE_BFS
        result.api_entries.append(entry)

    return result


def _collect_file_io_record(
    serialized_entry: SerializedAPIEntry,
    resolved: ResolvedAPICall,
    file_io_records: list[FileIORecord],
) -> None:
    """Extract a file I/O metadata record from a serialized File-domain entry.

    Only ``large_text`` tier records (non-binary files exceeding the size
    threshold) are collected.  Binary and inline entries are skipped because
    binary content cannot be inspected and inline content is already visible
    in the serialized API sequence.
    """
    from npm_pipeline.handlers.file_handler import _READ_FILE_OPS, _WRITE_FILE_OPS

    args = serialized_entry.arguments if isinstance(serialized_entry.arguments, dict) else {}
    file_path = args.get("file_path")
    if not file_path:
        return

    qname = resolved.qualified_name
    if qname in _READ_FILE_OPS:
        operation = "read"
        content_field = args.get("read_content")
    elif qname in _WRITE_FILE_OPS:
        operation = "write"
        content_field = args.get("write_content")
    else:
        return

    if not (isinstance(content_field, dict) and "content_type" in content_field):
        # only large files has the content_type
        return

    file_io_records.append(
        FileIORecord(
            file_path=file_path,
            operation=operation,
            content_size=content_field.get("size"),
            content_type=content_field.get("content_type"),
        )
    )


# ======================================================================
# Phase B: post-traversal orphan recovery + batched LLM + stitch-back
# ======================================================================

_ORPHAN_ADJACENCY_GAP = 20


def _resolve_with_confidence(
    api_call: "APICall", sensitive_call: dict, confidence: str
) -> "ResolvedAPICall":
    """Resolve *api_call* using *sensitive_call* and tag it with *confidence*."""
    resolved = resolve_api_call(api_call, sensitive_call)
    resolved.confidence = confidence
    return resolved


@dataclass
class _ChainEnrichment:
    """Phase-B scratch attribution metadata for one :class:`ChainMatch`.

    Computed once at the start of Phase-B by :func:`_enrich_chain_matches`
    and consumed by every subsequent orphan-recovery layer.  Keeping it
    out of :class:`ChainMatch` makes Phase-A a pure localization pass
    and keeps cross-cutting concerns (module-root expansion, registration
    inference) confined to the global phase.

    Attributes
    ----------
    module_roots:
        Owning-module prefixes for Layer-2 attribution.  Seeded from
        :func:`find_module_root` on the chain's ``chain_root_file`` (or
        :func:`find_package_root` when the root lives in user code) and
        expanded via :meth:`DependencyTree.closure_for_file` to cover
        the chain's declared transitive deps.  Empty for chains whose
        root file can't be localized - they silently drop out of Layer 2.
    registration_idx:
        The chain's earliest observable log index ("registration point")
        used by Layer 3.5 as a pseudo-anchor and by the bounded-claim
        window.  Derived as ``min(bfs_indices)`` when the static CG
        managed to reach into the chain; otherwise as the earliest log
        entry whose ``caller.file`` falls under any ``module_roots``.
        ``None`` when neither source is available.
    """

    module_roots: set[str] = field(default_factory=set)
    registration_idx: int | None = None


def _enrich_chain_matches(
    analysis_context: "AnalysisContext",
    idx_to_call: dict[int, "APICall"],
) -> dict[int, "_ChainEnrichment"]:
    """Compute Phase-B attribution metadata for every chain in one pass.

    Uses ``id(chain)`` as the key so we don't have to mutate
    :class:`ChainMatch` itself; the lifetime of each entry is exactly
    one :func:`recover_orphans_globally` call.

    Module-root expansion consults
    :class:`AnalysisContext.dependency_tree` (parsed from
    ``npm ls --all --json``) rather than the static call graph's
    transitive closure: ``npm ls`` is the ground truth for declared
    cross-package dependencies, while the static CG frequently misses
    cross-package edges that pass through dynamic dispatch
    (``axios -> follow-redirects``, ``got -> cacheable-request``).

    When the dep tree wasn't generated (empty tree), this degrades to
    a single direct module root - chains then only own what their own
    callee file lives under, matching the behavior before the dep_tree
    integration.
    """
    from npm_pipeline.utils.module_root_utils import (
        find_module_root,
        find_package_root,
    )

    record = analysis_context.dynamic_matching_record
    api_call_info = analysis_context.current_code_info.api_call_info
    dep_tree = analysis_context.dependency_tree

    enrichments: dict[int, _ChainEnrichment] = {}
    for chain in record.chain_matches:
        enrich = _ChainEnrichment()

        # ---- Module roots ---------------------------------------------
        root_file = chain.chain_root_file
        roots: set[str] = set()
        if root_file:
            primary = find_module_root(root_file)
            if primary is None:
                # Chain whose entry callee sits in user code - use the
                # analyzed-package root sentinel so Layer 2 can still
                # attribute sensitive calls made from user code.
                primary = find_package_root(root_file)
            if primary is not None:
                roots.add(primary)
            # Declared-dep closure: ``axios -> follow-redirects``-style
            # cross-package delegation.  Skipped entirely for user-code
            # chains (closure_for_file returns empty for non-node_modules
            # paths), so the analyzed-package sentinel stays isolated.
            if not dep_tree.is_empty():
                roots.update(dep_tree.closure_for_file(root_file))
        enrich.module_roots = roots

        # ---- Registration index ---------------------------------------
        # Preferring ``min(bfs_indices)`` means chains that the CG did
        # reach into are anchored on actual BFS-matched logs instead of
        # guessed module-root "first voices".  For pure-async chains the
        # module-root-earliest heuristic is the only signal available -
        # collisions between sibling chains on the same root are handled
        # downstream by ``shared`` confidence.
        reg_idx: int | None = None
        if chain.bfs_indices:
            reg_idx = min(chain.bfs_indices)
        elif roots and api_call_info is not None:
            earliest: int | None = None
            for root in roots:
                under_root = api_call_info.find_api_calls_under_path_prefix(root)
                if not under_root:
                    continue
                idx0 = under_root[0][0]
                if earliest is None or idx0 < earliest:
                    earliest = idx0
            reg_idx = earliest
        enrich.registration_idx = reg_idx

        enrichments[id(chain)] = enrich

        logger.debug(
            f"[Dynamic][PhaseB0] enrich node={chain.node_id} "
            f"root_file={root_file} "
            f"reg_idx={reg_idx} bfs={len(chain.bfs_indices)}"
        )

    return enrichments


def recover_orphans_globally(
    analysis_context: "AnalysisContext",
) -> dict[int, list[tuple[int, "ResolvedAPICall"]]]:
    """Phase B1: attribute unmatched API calls to third-party chains.

    Operates over the entire :class:`DynamicMatchingRecord` at once, so
    every chain's BFS anchors are visible to every other chain while
    deciding who owns an orphan.  Returns a mapping
    ``node_id -> list[(log_index, ResolvedAPICall)]`` containing the
    chain's BFS-matched calls **plus** any orphans attributed to it.
    Entries are sorted by log index (runtime order).

    Pipeline outline:

    - **Phase B0 (enrichment)**: :func:`_enrich_chain_matches` derives
      per-chain module roots (via the declared dependency tree) and
      registration points.  This is purely local bookkeeping; all
      runtime-order decisions happen in the layers below.
    - **Phase B1 (attribution)**: organized by "order and interval" -
      log-order intervals built from registration points, over which
      Layer 2 / 3 / 3.5 attribute orphans.

    Recovery layers, in order of increasing uncertainty:

    - **Layer 1** (implicit): an orphan is a log entry whose
      :meth:`APICallCollection.caller_key` is not claimed by any BFS
      match or single-call match in the record.
    - **Layer 2** *(confidence=``"module_root"``)*: attribute an orphan
      to a chain when its ``caller.file`` lives under that chain's
      enriched ``module_roots`` (own pkg plus declared transitive
      deps, or the analyzed-package root).  When multiple chains
      share the deepest matching root we defer to Layer 3 / 3.5
      tie-breakers.
    - **Layer 3** *(confidence=``"adjacency"``)*: extend a chain
      forward/backward in log-order from its BFS anchors, absorbing
      contiguous orphan runs whose gap to the last absorbed index is
      ``<= _ORPHAN_ADJACENCY_GAP``.  Preserves coverage for callbacks
      whose caller file is neither in ``node_modules`` nor in a
      declared dep (e.g. user-provided callbacks invoked synchronously
      by a third-party library).
    - **Layer 3.5** *(confidence=``"registration_adjacency"`` |
      ``"shared"``): for chains with no BFS anchors, use the chain's
      own registration index as a pseudo-anchor, then apply the
      ambiguity-resolution rules (module-root priority, nearest-
      registration, bounded-claim window, shared-attribution
      fallback).  ``shared`` is preserved for genuinely ambiguous
      back-to-back pure-async chains that a dep_tree-driven answer
      cannot disambiguate (two sibling chains registering
      simultaneously on the same module root).

    Orphans that remain unclaimed after all layers are dropped from the
    sequence - they are not attributable to any specific PDG node.
    """
    from npm_pipeline.utils.module_root_utils import (
        nested_module_root_depth,
        path_is_under,
    )

    record = analysis_context.dynamic_matching_record
    api_call_info = analysis_context.current_code_info.api_call_info
    if api_call_info is None or (not record.chain_matches and not record.single_matches):
        return {}

    # --- preparation: index the runtime log once ----------------------
    all_calls: list[tuple[int, APICall]] = list(api_call_info.iter_ordered())
    claimed_keys = record.global_matched_keys()
    idx_to_call = {idx: call for idx, call in all_calls}

    # Phase B0: compute per-chain module_roots + registration_idx in a
    # single pass before any attribution happens.
    enrichments = _enrich_chain_matches(analysis_context, idx_to_call)

    def _module_roots(chain: "ChainMatch") -> set[str]:
        enrich = enrichments.get(id(chain))
        return enrich.module_roots if enrich else set()

    def _reg_idx(chain: "ChainMatch") -> int | None:
        enrich = enrichments.get(id(chain))
        return enrich.registration_idx if enrich else None

    # Per-call sensitive-call lookup cache - the same qualified name
    # appears many times in a realistic log, and ``sensitive_call_finder``
    # is not free.
    sensitive_cache: dict[str, dict | None] = {}

    def _sensitive_for(call: APICall) -> dict | None:
        key = f"{call.module}.{call.function}"
        if key not in sensitive_cache:
            sensitive_cache[key] = sensitive_call_finder.query(key)
        return sensitive_cache[key]

    # Orphans = log entries that are sensitive API calls AND not claimed.
    orphans: list[tuple[int, APICall]] = []
    for idx, call in all_calls:
        if APICallCollection.caller_key(call) in claimed_keys:
            continue
        if _sensitive_for(call) is None:
            continue
        orphans.append((idx, call))

    logger.info(
        f"[Dynamic][PhaseB1] orphans={len(orphans)} "
        f"chains={len(record.chain_matches)} singles={len(record.single_matches)}"
    )

    # Per-chain scratch state: final log index -> (call, confidence).
    # Using a dict indexed by log_index lets Layer-3 + Layer-3.5 merge
    # cleanly while keeping the output deterministic (we sort at the end).
    chain_acc: dict[int, dict[int, tuple[APICall, str]]] = {
        id(chain): {} for chain in record.chain_matches
    }

    # Seed each chain's accumulator with its BFS anchors (confidence=bfs).
    for chain in record.chain_matches:
        bucket = chain_acc[id(chain)]
        for idx in chain.bfs_indices:
            call = idx_to_call.get(idx)
            if call is not None:
                bucket[idx] = (call, CONFIDENCE_BFS)

    # ------------------------------------------------------------------
    # Registration ordering: build the log-order intervals up front.
    # ------------------------------------------------------------------
    # Each chain with a known registration_idx claims
    # ``[registration_idx, next_registration_idx)``; this is the
    # "order and interval" structure over which Layer 3 / 3.5 operate.  We
    # precompute the sorted list once - it's read many times below.
    reg_sorted = sorted(
        ((_reg_idx(c), c) for c in record.chain_matches if _reg_idx(c) is not None),
        key=lambda item: item[0],
    )

    def _next_registration_after(idx: int) -> int | None:
        for reg_idx, _ in reg_sorted:
            if reg_idx > idx:
                return reg_idx
        return None

    def _chain_claim_bound(chain: "ChainMatch") -> int | None:
        """Return the exclusive upper log-index beyond which *chain* may not claim."""
        r = _reg_idx(chain)
        if r is None:
            return None
        return _next_registration_after(r)

    # ------------------------------------------------------------------
    # Layer 2: module-root attribution (dep_tree-driven)
    # ------------------------------------------------------------------
    # For every orphan, find every chain whose enriched module_roots
    # contain the orphan's caller.file.  When exactly one chain matches
    # (possibly the innermost of a nested-node_modules stack) we assign
    # it immediately with module_root confidence and consider the
    # orphan claimed.  Multiple matches go to the ambiguity pass below.

    def _candidate_chains_for_path(path: str | None):
        """Return ``[(depth, chain)]`` for chains whose enriched
        ``module_roots`` contain *path*.

        A chain's roots now come from the declared dependency tree plus
        the direct callee's owning prefix, so cross-package delegation
        like ``axios -> follow-redirects`` is represented even when the
        static CG misses the edge.  ``depth`` remains the nested
        ``node_modules`` depth of the matched prefix so the
        innermost-wins rule still distinguishes truly nested installs
        like ``node_modules/axios/node_modules/follow-redirects/``.
        """
        if path is None:
            return []
        from npm_pipeline.utils.module_root_utils import normalize_for_prefix_match

        norm_path = normalize_for_prefix_match(path)
        in_node_modules = "/node_modules/" in norm_path or norm_path.startswith("node_modules/")

        result: list[tuple[int, "ChainMatch"]] = []
        for chain in record.chain_matches:
            roots = _module_roots(chain)
            if not roots:
                continue
            best_depth = -1
            for root in roots:
                if root == "":
                    # Analyzed-package root matches non-node_modules files.
                    if not in_node_modules:
                        best_depth = max(best_depth, 0)
                    continue
                if path_is_under(path, root):
                    best_depth = max(best_depth, nested_module_root_depth(root))
            if best_depth >= 0:
                result.append((best_depth, chain))
        return result

    remaining: list[tuple[int, APICall]] = []  # orphans not settled by Layer 2
    module_root_conflicts: list[tuple[int, APICall, list["ChainMatch"]]] = []

    for idx, call in orphans:
        caller_file = (call.caller or {}).get("file")
        cands = _candidate_chains_for_path(caller_file)
        if not cands:
            remaining.append((idx, call))
            continue
        # "Innermost wins" for nested node_modules: max depth first.
        cands.sort(key=lambda p: p[0], reverse=True)
        top_depth = cands[0][0]
        top = [c for d, c in cands if d == top_depth]
        if len(top) == 1:
            ch = top[0]
            chain_acc[id(ch)][idx] = (call, CONFIDENCE_MODULE_ROOT)
        else:
            module_root_conflicts.append((idx, call, top))

    # ------------------------------------------------------------------
    # Layer 3: runtime-order adjacency from BFS anchors
    # ------------------------------------------------------------------
    # Walk each chain's BFS indices and absorb any *remaining* orphan
    # whose index is within `_ORPHAN_ADJACENCY_GAP` of a previously
    # absorbed index on the same side.  This bridges short async bursts
    # like ``fs.readdir -> child reads`` where the children aren't on
    # the static call graph and also aren't in a declared-dep package
    # (e.g. user-provided callbacks invoked synchronously).

    # Build an index-sorted list of remaining orphans for quick slicing.
    remaining.sort(key=lambda p: p[0])
    remaining_by_idx: dict[int, APICall] = {idx: call for idx, call in remaining}
    still_remaining: set[int] = set(remaining_by_idx.keys())

    for chain in record.chain_matches:
        if not chain.bfs_indices:
            continue
        bucket = chain_acc[id(chain)]
        anchors = sorted(chain.bfs_indices)
        # Walk forward from each anchor
        current = set(anchors)
        changed = True
        while changed:
            changed = False
            for anchor in sorted(current):
                # forward
                probe = anchor
                for orphan_idx in sorted(still_remaining):
                    if orphan_idx <= probe:
                        continue
                    if orphan_idx - probe > _ORPHAN_ADJACENCY_GAP:
                        break
                    call = remaining_by_idx[orphan_idx]
                    bucket[orphan_idx] = (call, CONFIDENCE_ADJACENCY)
                    current.add(orphan_idx)
                    probe = orphan_idx
                    still_remaining.discard(orphan_idx)
                    changed = True
                # backward
                probe = anchor
                for orphan_idx in sorted(still_remaining, reverse=True):
                    if orphan_idx >= probe:
                        continue
                    if probe - orphan_idx > _ORPHAN_ADJACENCY_GAP:
                        break
                    call = remaining_by_idx[orphan_idx]
                    bucket[orphan_idx] = (call, CONFIDENCE_ADJACENCY)
                    current.add(orphan_idx)
                    probe = orphan_idx
                    still_remaining.discard(orphan_idx)
                    changed = True

    # ------------------------------------------------------------------
    # Layer 3.5: registration-point anchors + ambiguity resolution
    # ------------------------------------------------------------------
    # For each chain WITHOUT BFS anchors (pure-async), promote its
    # registration index to a pseudo-anchor.  For remaining orphans and
    # module-root conflicts, apply the four-step rule:
    #
    #   1. Module-root priority (already applied above - falls through
    #      here only when ambiguous at Layer 2).
    #   2. Nearest-registration (with "preceding chain wins" on tie).
    #   3. Bounded-claim window (never cross the next chain's
    #      registration index).
    #   4. Shared-attribution fallback (attribute to every tied chain
    #      with confidence="shared") - the deliberate concession for
    #      truly concurrent pure-async siblings the dep_tree cannot
    #      disambiguate.

    def _nearest_candidates(idx: int, candidates: list["ChainMatch"]) -> list["ChainMatch"]:
        """Return the subset of *candidates* with the smallest |anchor - idx|.

        ``anchor`` is the chain's registration index (Layer 3.5) or the
        nearest BFS index (Layer 3 leftover).  On an equal distance,
        the preceding chain (smaller anchor) wins per the "async
        callbacks fire after registration" heuristic.
        """
        scored: list[tuple[int, int, "ChainMatch"]] = []
        for ch in candidates:
            anchors: list[int] = list(ch.bfs_indices)
            r = _reg_idx(ch)
            if r is not None:
                anchors.append(r)
            if not anchors:
                continue
            # Closest anchor distance; tiebreak by direction (preceding wins).
            dist = min(abs(a - idx) for a in anchors)
            # "preceding wins" -> prefer anchors <= idx (direction score 0)
            has_preceding = any(a <= idx for a in anchors)
            direction = 0 if has_preceding else 1
            scored.append((dist, direction, ch))
        if not scored:
            return []
        scored.sort(key=lambda t: (t[0], t[1]))
        best_dist, best_dir, _ = scored[0]
        return [c for d, r, c in scored if d == best_dist and r == best_dir]

    # Register the pseudo-anchor for chains with no BFS anchors.
    # Multiple pure-async chains can (and often do) derive the same
    # registration index because they share a module root and the
    # anchor is "earliest sensitive log under that root".  We bucket by
    # index first so collisions surface as ``shared`` confidence
    # instead of one chain silently overwriting another in the
    # accumulator dict.
    pure_async_seed: dict[int, list[ChainMatch]] = {}
    for chain in record.chain_matches:
        r = _reg_idx(chain)
        if chain.bfs_indices or r is None:
            continue
        pure_async_seed.setdefault(r, []).append(chain)

    for reg_idx, chains in pure_async_seed.items():
        reg_call = idx_to_call.get(reg_idx)
        if reg_call is None or _sensitive_for(reg_call) is None:
            continue
        conf = CONFIDENCE_REGISTRATION_ADJACENCY if len(chains) == 1 else CONFIDENCE_SHARED
        for ch in chains:
            # Don't downgrade a higher-confidence assignment (e.g.
            # ``module_root`` already placed by Layer 2) to
            # ``registration_adjacency`` / ``shared``.  Layer 2 gets
            # first say; the pure-async seed only fills in holes.
            if reg_idx in chain_acc[id(ch)]:
                continue
            chain_acc[id(ch)][reg_idx] = (reg_call, conf)

    # Resolve module-root conflicts first - prefer nearest-registration.
    for idx, call, tied in module_root_conflicts:
        winners = _nearest_candidates(idx, tied)
        if len(winners) == 1:
            chain_acc[id(winners[0])][idx] = (call, CONFIDENCE_MODULE_ROOT)
        elif len(winners) > 1:
            for ch in winners:
                chain_acc[id(ch)][idx] = (call, CONFIDENCE_SHARED)
        # else: drop (no chain has any usable anchor)

    # Final pass: orphans never touched by Layer 2 or Layer 3.
    for idx, call in list(remaining_by_idx.items()):
        if idx not in still_remaining:
            continue  # already absorbed by Layer 3

        # Find chains whose claim window could plausibly cover this
        # orphan: registration_idx <= idx < next chain's registration.
        candidates: list["ChainMatch"] = []
        for ch in record.chain_matches:
            r = _reg_idx(ch)
            if r is None:
                continue
            if r > idx:
                continue
            bound = _chain_claim_bound(ch)
            if bound is not None and idx >= bound:
                continue
            candidates.append(ch)

        if not candidates:
            still_remaining.discard(idx)
            continue

        winners = _nearest_candidates(idx, candidates)
        if len(winners) == 1:
            chain_acc[id(winners[0])][idx] = (call, CONFIDENCE_REGISTRATION_ADJACENCY)
        else:
            for ch in winners:
                chain_acc[id(ch)][idx] = (call, CONFIDENCE_SHARED)
        still_remaining.discard(idx)

    # ------------------------------------------------------------------
    # Build the ResolvedAPICall sequences per node.
    # ------------------------------------------------------------------
    out: dict[int, list[tuple[int, ResolvedAPICall]]] = {}
    for chain in record.chain_matches:
        bucket = chain_acc[id(chain)]
        if not bucket:
            continue
        seq: list[tuple[int, ResolvedAPICall]] = []
        for idx in sorted(bucket.keys()):
            call, conf = bucket[idx]
            sc = _sensitive_for(call)
            if sc is None:
                continue
            seq.append((idx, _resolve_with_confidence(call, sc, conf)))
        if seq:
            out[chain.node_id] = seq

    logger.info(
        f"[Dynamic][PhaseB1] attributed chains={len(out)} orphans_unclaimed={len(still_remaining)}"
    )
    return out


# ----------------------------------------------------------------------
# Phase B2: parallel LLM batch with sequence dedup
# ----------------------------------------------------------------------


def _fingerprint_sequence(sequence: list[ResolvedAPICall]) -> str:
    """Canonicalize and hash a resolved sequence for LLM-call dedup.

    Two sequences with identical serialization-facing content (same
    qualified name, domain, arguments, and confidence tag per entry, in
    the same order) collapse to a single LLM request.  Confidence is
    included because the prompt behaviour differs by confidence tag.
    """
    import hashlib

    serialized = serialize_api_sequence(sequence)
    payload = json.dumps(
        serialized.to_llm_dict(),
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def run_behavior_generation_batch(
    node_sequences: dict[int, list[ResolvedAPICall]],
    parallel_workers: int = 8,
) -> dict[int, dict | None]:
    """Phase B2: deduped + parallelized LLM interpretation.

    Groups identical sequences by fingerprint, issues one LLM call per
    unique sequence in a thread pool, and then fans the result out to
    every node that shares the fingerprint.  Returns a dict keyed by
    ``node_id`` holding the same shape that
    :func:`generate_behavior_description_from_sequence` used to return
    (or ``None`` when the LLM call failed / returned no
    ``behavior_description``).
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if not node_sequences:
        return {}

    # fingerprint -> list of node_ids sharing it
    fp_to_nodes: dict[str, list[int]] = {}
    # fingerprint -> a representative sequence (and its node_id so we can
    # tag file_io_records correctly later).
    fp_to_sequence: dict[str, tuple[int, list[ResolvedAPICall]]] = {}

    for node_id, seq in node_sequences.items():
        if not seq:
            continue
        fp = _fingerprint_sequence(seq)
        fp_to_nodes.setdefault(fp, []).append(node_id)
        fp_to_sequence.setdefault(fp, (node_id, seq))

    logger.info(
        f"[Dynamic][PhaseB2] sequences_total={sum(len(v) for v in fp_to_nodes.values())} "
        f"unique_fingerprints={len(fp_to_sequence)} workers={parallel_workers}"
    )

    results_by_fp: dict[str, dict | None] = {}
    max_workers = max(1, min(parallel_workers, len(fp_to_sequence)))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_fp = {
            ex.submit(generate_behavior_description_from_sequence, seq, rep_node): fp
            for fp, (rep_node, seq) in fp_to_sequence.items()
        }
        for fut in as_completed(future_to_fp):
            fp = future_to_fp[fut]
            try:
                results_by_fp[fp] = fut.result()
            except Exception as exc:  # defensive: never let one failure kill the batch
                logger.warning(f"[Dynamic][PhaseB2] LLM call failed for fingerprint={fp}: {exc}")
                results_by_fp[fp] = None

    # Fan out the result to every node that shares the fingerprint.
    # For non-representative nodes we still clone the structure and
    # rebind ``node_id`` on the file_io_records so downstream consumers
    # see the right owner.
    out: dict[int, dict | None] = {}
    for fp, node_ids in fp_to_nodes.items():
        base = results_by_fp.get(fp)
        if base is None:
            logger.warning(
                f"[Dynamic][PhaseB2] No behavior for fingerprint={fp[:12]} "
                f"(affects {len(node_ids)} node(s): {node_ids})"
            )
            for nid in node_ids:
                out[nid] = None
            continue

        behavior_text = (base.get("behavior_description") or "").strip()
        for nid in node_ids:
            cloned = copy.deepcopy(base)
            file_io = cloned.get("file_io_records") or []
            for rec in file_io:
                # ``rec`` may be a FileIORecord instance (the current
                # generate_behavior_description_from_sequence emits
                # these) or a plain dict.  Set node_id on whichever
                # form we find.
                if isinstance(rec, FileIORecord):
                    rec.node_id = nid
                elif isinstance(rec, dict):
                    rec["node_id"] = nid
            for kf in cloned.get("key_files") or []:
                if isinstance(kf, dict):
                    kf["node_id"] = nid
            out[nid] = cloned
            logger.info(f"[Dynamic][PhaseB2] node_id={nid} behavior_description={behavior_text}")

    return out


# ----------------------------------------------------------------------
# Phase B3: stitch LLM results back into the PDG
# ----------------------------------------------------------------------


def apply_behavior_results(
    node_sequences: dict[int, list[ResolvedAPICall]],
    behavior_results: dict[int, dict | None],
    analysis_context: "AnalysisContext",
) -> None:
    """Phase B3: write sequence + behavior artifacts back to PDG nodes.

    For every chain node we:

    - Call ``set_resolved_api_call_sequence`` with the (possibly
      orphan-augmented) sequence.
    - Copy ``behavior_description``, ``key_files``, ``file_io_records``
      onto the node if the LLM call produced anything.
    - Re-run :func:`_bind_large_file_contents` so large-text file bodies
      become attached to the node.

    Node lookup uses the direct reference stashed on each
    :class:`ChainMatch` during Phase A (see
    :func:`_resolve_third_party_call_chain`), so no ``ProgramContext``
    walk is needed.
    """
    record = analysis_context.dynamic_matching_record
    id_to_node = {c.node_id: c.node for c in record.chain_matches if c.node is not None}

    stitched = 0
    for node_id, sequence in node_sequences.items():
        node = id_to_node.get(node_id)
        if node is None:
            logger.debug(f"[Dynamic][PhaseB3] PDG node {node_id} not found; skipping")
            continue
        node.set_resolved_api_call_sequence(sequence)

        result = behavior_results.get(node_id)
        if result:
            node.set_behavior_description(result.get("behavior_description"))
            node.set_key_files(result.get("key_files"))
            node.set_file_io_records(result.get("file_io_records"))
            _bind_large_file_contents(node, result.get("file_io_records", []) or [], sequence)
        stitched += 1

    logger.info(f"[Dynamic][PhaseB3] stitched {stitched}/{len(node_sequences)} nodes")


# ----------------------------------------------------------------------
# Phase-B driver
# ----------------------------------------------------------------------


def run_pending_behavior_generation(
    analysis_context: "AnalysisContext",
    enable_orphan_recovery: bool = True,
    parallel_workers: int = 8,
) -> None:
    """Entry point for Phase B: recover orphans, batch LLM, stitch back.

    Call this exactly once after the dynamic PDG traversal for a given
    entry script finishes and before the dynamic interpreter / judgment
    prompts run.

    When *enable_orphan_recovery* is ``False`` the pipeline degrades to
    "BFS-only" mode: each chain sees only its own BFS-matched calls (no
    orphan attribution, no ``shared`` / ``registration_adjacency``
    tags).  Useful for ablation and comparison runs.
    """
    record = analysis_context.dynamic_matching_record
    if not record.chain_matches:
        logger.debug("[Dynamic][PhaseB] no chain matches queued; skipping")
        return

    if enable_orphan_recovery:
        recovered = recover_orphans_globally(analysis_context)
    else:
        # BFS-only: just materialize each chain's bfs_indices as a
        # sequence with bfs confidence; skip all orphan layers.
        api_call_info = analysis_context.current_code_info.api_call_info
        idx_to_call = {idx: call for idx, call in api_call_info.iter_ordered()}
        recovered = {}
        for chain in record.chain_matches:
            seq: list[tuple[int, ResolvedAPICall]] = []
            for idx in sorted(chain.bfs_indices):
                call = idx_to_call.get(idx)
                if call is None:
                    continue
                sc = sensitive_call_finder.query(f"{call.module}.{call.function}")
                if sc is None:
                    continue
                seq.append((idx, _resolve_with_confidence(call, sc, CONFIDENCE_BFS)))
            if seq:
                recovered[chain.node_id] = seq

    # Drop the log-order indices before handing to Phase B2 - the LLM
    # prompt only needs the resolved calls, not their runtime positions.
    node_sequences: dict[int, list[ResolvedAPICall]] = {
        nid: [call for _, call in pairs] for nid, pairs in recovered.items()
    }

    behavior_results = run_behavior_generation_batch(
        node_sequences, parallel_workers=parallel_workers
    )
    apply_behavior_results(node_sequences, behavior_results, analysis_context)

    # Clear the record so the next entry script starts fresh.
    record.clear()
