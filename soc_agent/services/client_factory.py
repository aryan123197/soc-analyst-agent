"""Compatibility helper for Starlette TestClient with modern httpx versions.

Ensures TestClient works seamlessly across both Python virtualenvs and system environments
where starlette and httpx version signatures may differ.
"""
import httpx
from starlette.testclient import TestClient

try:
    _check = TestClient(None)
except TypeError:
    _orig_httpx_init = httpx.Client.__init__

    def _patched_httpx_init(self, *args, **kwargs):
        if "app" in kwargs:
            app_arg = kwargs.pop("app")
            if ("transport" not in kwargs or kwargs["transport"] is None) and app_arg is not None:
                try:
                    from starlette.testclient import _ASGIAdapter
                    kwargs["transport"] = _ASGIAdapter(app_arg)
                except Exception:
                    pass
        return _orig_httpx_init(self, *args, **kwargs)

    httpx.Client.__init__ = _patched_httpx_init
except Exception:
    pass


def make_test_client(app):
    return TestClient(app)
