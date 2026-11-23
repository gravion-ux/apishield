"""APIShield — a zero-dependency API security gateway.

Sits in front of an HTTP API, inspects traffic in transit and detects the
attack classes that dominate real API breaches: BOLA/IDOR, broken JWT
handling, authentication abuse, sensitive-data exposure and missing
security headers. Monitor mode logs; enforce mode blocks on critical rules.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
