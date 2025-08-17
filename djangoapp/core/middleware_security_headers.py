from django.utils.deprecation import MiddlewareMixin

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "frame-ancestors 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "upgrade-insecure-requests"
)

class SecurityHeadersMiddleware(MiddlewareMixin):
    def process_response(self, request, response):
        response.setdefault("X-Frame-Options", "DENY")
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("Referrer-Policy", "strict-origin")
        response.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), gyroscope=(), magnetometer=(), payment=()"
        )
        return response
