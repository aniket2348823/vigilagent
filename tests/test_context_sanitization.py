"""Unit tests for ChildSpec context sanitization."""

from backend.core.delegation_manager import ChildSpec


def test_safe_keys_pass_through():
    spec = ChildSpec(agent_class='Test', objective='test', context={'target': 'example.com', 'scope': 'full', 'scan_id': 'abc', 'phase': 'recon'})
    safe = spec.sanitize_context()
    assert safe.get('target') == 'example.com'
    assert safe.get('scope') == 'full'
    print('Test 1 PASSED: Safe keys pass through')


def test_blocked_keys_dropped():
    spec = ChildSpec(agent_class='Test', objective='test', context={'target': 'ex.com', 'api_key': 'sk-123', 'tokens': ['jwt'], 'credentials': {'u': 'a'}, 'passwords': ['p'], 'private_keys': ['k'], 'session_cookies': ['c'], 'jwt_tokens': ['j'], 'auth_headers': ['h'], 'vault_tokens': ['v']})
    safe = spec.sanitize_context()
    blocked = ['api_key','tokens','credentials','passwords','private_keys','session_cookies','jwt_tokens','auth_headers','vault_tokens']
    for k in blocked:
        assert k not in safe, f'{k} not dropped'
    assert 'target' in safe
    print('Test 2 PASSED: All 9 blocked keys dropped')


def test_unknown_keys_dropped():
    spec = ChildSpec(agent_class='Test', objective='test', context={'target': 'ex.com', 'custom_field': 'v'})
    safe = spec.sanitize_context()
    assert 'custom_field' not in safe
    assert 'target' in safe
    print('Test 3 PASSED: Unknown keys dropped')


def test_empty_context():
    assert ChildSpec(agent_class='Test', objective='test', context={}).sanitize_context() == {}
    print('Test 4 PASSED: Empty context')


def test_mixed_context():
    spec = ChildSpec(agent_class='Test', objective='test', context={'target': 'ex.com', 'api_key': 'x', 'custom': 'y', 'scope': 'l'})
    safe = spec.sanitize_context()
    assert safe == {'target': 'ex.com', 'scope': 'l'}
    print('Test 5 PASSED: Mixed context')


def test_original_not_mutated():
    orig = {'target': 'ex.com', 'api_key': 'sk'}
    ChildSpec(agent_class='Test', objective='test', context=orig).sanitize_context()
    assert 'api_key' in orig
    print('Test 6 PASSED: Original not mutated')


if __name__ == '__main__':
    test_safe_keys_pass_through()
    test_blocked_keys_dropped()
    test_unknown_keys_dropped()
    test_empty_context()
    test_mixed_context()
    test_original_not_mutated()
    print('\nAll 6 sanitize_context tests PASSED')
