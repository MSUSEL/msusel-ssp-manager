from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from .compliance_sdk import ComplianceSDK

class OPAMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, opa_url: str, secret_key: str, algorithm: str):
        super().__init__(app)
        self.sdk = ComplianceSDK(opa_url, secret_key, algorithm)

    async def dispatch(self, request: Request, call_next):
        # Example action/resource for demo purposes
        action = request.method
        resource = request.url.path

        # Validate the request and query OPA
        try:
            self.sdk.authorize_request(request, action, resource)
        except HTTPException as e:
            return e

        # Proceed with the request
        return await call_next(request)
