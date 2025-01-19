import requests

class OPAQuery:
    def __init__(self, opa_url: str):
        self.opa_url = opa_url

    def query(self, input_data: dict) -> bool:
        """
        Queries the OPA engine and returns the result.
        """
        try:
            response = requests.post(self.opa_url, json={"input": input_data})
            response.raise_for_status()
            return response.json().get("result", False)
        except Exception as e:
            print(f"Error querying OPA: {e}")
            return False
