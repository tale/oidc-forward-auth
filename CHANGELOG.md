# 0.0.4 (June 11, 2025)
- Use a separate cookie for login state to prevent issues with the OIDC flow.
- Fixed an issue where successive quick requests would break the login state.
- Introduce better logging about issues during the OIDC flow.

# 0.0.3 (March 26, 2025)
- Add a proper README.md file with a set of instructions
- Add some more debug logging to investigate future issues

# 0.0.2 (March 15, 2025)
- Added a custom logger with proper debug levels
- Fixed an issue preventing `GATEWAY_URL` from being set without a port

# 0.0.1 (March 14, 2025)
- Initial release
