import csv

from npm_pipeline.classes.object import Object


class SensitiveDatabase:
    def __init__(self, config_file: str):
        self.dict: dict[tuple[str, str], dict] = {}
        with open(config_file, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader)

            for row in reader:
                if len(row) == 5:
                    module, property_method, qualified_name, domain, behavior = row
                    self.dict[(module, property_method)] = {
                        "qualified_name": qualified_name,
                        "domain": domain,
                        "behavior": behavior,
                    }

    def query(self, item):
        """
        find the module and property_method in dict, and get the domain
        """
        if item is None:
            return None

        if isinstance(item, Object):
            item = item.get_qualified_name()
        if isinstance(item, str):
            split_result = item.split(".")
            if len(split_result) == 1:
                module = split_result[0]
                property_method = None
            else:
                module = split_result[0]
                property_method = ".".join(split_result[1:])

            if module and property_method and (module, property_method) in self.dict:
                return self.dict[(module, property_method)]

            else:
                return None
        else:
            return None


sensitive_call_finder = SensitiveDatabase("./sensitive_call.csv")
sensitive_property_access_finder = SensitiveDatabase("./sensitive_property_access.csv")
