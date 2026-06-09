"""Unit tests for TaskGraph.execute_dag dependency ordering."""

import asyncio
from unittest.mock import AsyncMock, MagicMock
from backend.core.planner import TaskGraph


def _make_cmd(name, argv=None, timeout=10, depends_on=None):
    cmd = MagicMock()
    cmd.argv = argv or [name]
    cmd.timeout = timeout
    cmd.depends_on = depends_on or []
    return cmd


async def _run_tests():
    # Test 1: No dependencies = parallel
    graph = TaskGraph()
    graph._run_dag_tool = AsyncMock(return_value=None)
    commands = {
        "subfinder": _make_cmd("subfinder"),
        "amass": _make_cmd("amass"),
    }
    results = await graph.execute_dag(commands)
    assert len(results) == 2
    assert "subfinder" in results
    assert "amass" in results
    print('Test 1 PASSED: No dependencies = parallel')

    # Test 2: Respects dependencies
    graph2 = TaskGraph()
    execution_order = []
    async def mock_run(name, cmd):
        execution_order.append(f"start_{name}")
        await asyncio.sleep(0.01)
        execution_order.append(f"end_{name}")
        return {"name": name}
    graph2._run_dag_tool = mock_run
    commands2 = {
        "subfinder": _make_cmd("subfinder", depends_on=[]),
        "dnsx": _make_cmd("dnsx", depends_on=["subfinder"]),
    }
    results2 = await graph2.execute_dag(commands2)
    assert len(results2) == 2
    subfinder_end = execution_order.index("end_subfinder")
    dnsx_start = execution_order.index("start_dnsx")
    assert dnsx_start > subfinder_end
    print('Test 2 PASSED: Respects dependency ordering')

    # Test 3: Empty commands
    graph3 = TaskGraph()
    results3 = await graph3.execute_dag({})
    assert results3 == {}
    print('Test 3 PASSED: Empty commands')

    print('\nAll 3 DAG execution tests PASSED')


if __name__ == '__main__':
    asyncio.run(_run_tests())
