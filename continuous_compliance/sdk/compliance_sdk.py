from .opa_query import OPAQuery
from .token_handler import TokenHandler

class ComplianceSDK:
    def __init__(self, opa_url: str, secret_key: str, algorithm: str):
        self.opa_query = OPAQuery(opa_url)
        self.token_handler = TokenHandler(secret_key, algorithm)

    def authorize_request(self, request, action: str, resource: str) -> dict:
        """
        Extracts and validates the token, then queries OPA for authorization.
        """
        # Extract and validate the token
        token = self.token_handler.extract_token(request)
        payload = self.token_handler.decode_token(token)

        # Query OPA for authorization
        input_data = {
            "token": payload,
            "action": action,
            "resource": resource
        }
        if not self.opa_query.query(input_data):
            raise HTTPException(status_code=403, detail="Access denied by policy")

        return payload
