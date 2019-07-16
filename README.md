# WebSocket client for C

## This project is based on [https://github.com/payden/libwsclient](https://github.com/payden/libwsclient)

Due to that project is not in maintenance any more, I  would continue the work here:

* Fix some bugs, includes memory leakage, mutex lock, etc.

* Reconstruct project source code to provide simple interfaces.

* Add send binary data interface.

* Implement ping/pong according [RFC-6455](https://tools.ietf.org/html/rfc6455).

* Add client heart beat for potential use.

* Add external http request header field for authorization.
