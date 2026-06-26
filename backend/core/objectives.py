from dataclasses import dataclass, field

from backend.schemas.findings import Evidence, ObjectivePhase, ObjectiveStatus, ScanObjective


class ObjectiveTransitionError(ValueError):
    pass


VALID_TRANSITIONS = {
    ObjectiveStatus.PENDING: {ObjectiveStatus.IN_PROGRESS, ObjectiveStatus.BLOCKED, ObjectiveStatus.CANCELLED},
    ObjectiveStatus.IN_PROGRESS: {ObjectiveStatus.COMPLETED, ObjectiveStatus.BLOCKED, ObjectiveStatus.CANCELLED},
    ObjectiveStatus.BLOCKED: {ObjectiveStatus.IN_PROGRESS, ObjectiveStatus.CANCELLED, ObjectiveStatus.COMPLETED},
    ObjectiveStatus.COMPLETED: set(),
    ObjectiveStatus.CANCELLED: set(),
}


@dataclass
class ObjectivePlan:
    objectives: list[ScanObjective] = field(default_factory=list)
    _counter: int = 0

    def add(
        self,
        *,
        title: str,
        phase: ObjectivePhase,
        description: str = "",
        acceptance_criteria: list[str] | None = None,
        priority: int = 5,
        blocked_by: list[str] | None = None,
        endpoint_group: str = "",
        parent_id: str | None = None,
        owner: str = "",
    ) -> ScanObjective:
        if parent_id and self.by_id(parent_id) is None:
            raise ObjectiveTransitionError(f"Unknown parent objective: {parent_id}")
        self._counter += 1
        obj = ScanObjective(
            id=f"OBJ-{self._counter:03d}",
            phase=phase,
            title=title,
            description=description,
            acceptance_criteria=acceptance_criteria or [],
            priority=priority,
            blocked_by=blocked_by or [],
            endpoint_group=endpoint_group,
            parent_id=parent_id,
            owner=owner,
        )
        self.objectives.append(obj)
        return obj

    def by_id(self, objective_id: str) -> ScanObjective | None:
        return next((obj for obj in self.objectives if obj.id == objective_id), None)

    def ready(self) -> list[ScanObjective]:
        completed = {obj.id for obj in self.objectives if obj.status == ObjectiveStatus.COMPLETED}
        return [
            obj
            for obj in sorted(self.objectives, key=lambda item: item.priority)
            if obj.status == ObjectiveStatus.PENDING and all(dep in completed for dep in obj.blocked_by)
        ]

    def transition(self, objective_id: str, status: ObjectiveStatus) -> ScanObjective:
        obj = self.by_id(objective_id)
        if obj is None:
            raise ObjectiveTransitionError(f"Unknown objective: {objective_id}")
        if status == ObjectiveStatus.COMPLETED:
            open_children = [
                child.id
                for child in self.objectives
                if child.parent_id == obj.id
                and child.status not in {ObjectiveStatus.COMPLETED, ObjectiveStatus.CANCELLED}
            ]
            if open_children:
                raise ObjectiveTransitionError(
                    f"Cannot complete {objective_id}; open children: {', '.join(open_children)}"
                )
            if obj.acceptance_criteria and not obj.findings and not obj.evidence:
                raise ObjectiveTransitionError(f"Cannot complete {objective_id}; evidence or findings are required")
        if status not in VALID_TRANSITIONS[obj.status]:
            raise ObjectiveTransitionError(f"Invalid transition {obj.status.value} -> {status.value}")
        obj.status = status
        return obj

    def expand(self, parent_id: str, children: list[dict]) -> list[ScanObjective]:
        parent = self.by_id(parent_id)
        if parent is None:
            raise ObjectiveTransitionError(f"Unknown parent objective: {parent_id}")
        created: list[ScanObjective] = []
        for index, child in enumerate(children, start=1):
            created.append(
                self.add(
                    title=str(child["title"]),
                    phase=ObjectivePhase(child.get("phase", parent.phase.value)),
                    description=str(child.get("description", "")),
                    acceptance_criteria=list(child.get("acceptance_criteria") or []),
                    priority=int(child.get("priority", parent.priority + index)),
                    blocked_by=list(child.get("blocked_by") or []),
                    endpoint_group=child.get("endpoint_group", parent.endpoint_group),
                    parent_id=parent_id,
                    owner=child.get("owner", ""),
                )
            )
        return created

    def collapse(self, parent_id: str) -> list[str]:
        if self.by_id(parent_id) is None:
            raise ObjectiveTransitionError(f"Unknown parent objective: {parent_id}")
        cancelled: list[str] = []
        stack = [parent_id]
        while stack:
            current = stack.pop()
            for obj in self.objectives:
                if obj.parent_id == current:
                    stack.append(obj.id)
                    if obj.status in {ObjectiveStatus.PENDING, ObjectiveStatus.IN_PROGRESS, ObjectiveStatus.BLOCKED}:
                        obj.status = ObjectiveStatus.CANCELLED
                        cancelled.append(obj.id)
        return cancelled

    def attach_finding(self, objective_id: str, finding_id: str) -> ScanObjective:
        obj = self.by_id(objective_id)
        if obj is None:
            raise ObjectiveTransitionError(f"Unknown objective: {objective_id}")
        if finding_id not in obj.findings:
            obj.findings.append(finding_id)
        return obj

    def attach_evidence(self, objective_id: str, evidence: Evidence) -> ScanObjective:
        obj = self.by_id(objective_id)
        if obj is None:
            raise ObjectiveTransitionError(f"Unknown objective: {objective_id}")
        obj.evidence.append(evidence)
        return obj

    def format_status(self) -> str:
        total = len(self.objectives)
        completed = sum(1 for obj in self.objectives if obj.status == ObjectiveStatus.COMPLETED)
        blocked = sum(1 for obj in self.objectives if obj.status == ObjectiveStatus.BLOCKED)
        lines = [f"Progress: {completed}/{total} completed, {blocked} blocked", ""]
        lines.append("| ID | Phase | Title | Status | Priority | Owner | Blocked By |")
        lines.append("|---|---|---|---|---|---|---|")
        for obj in sorted(self.objectives, key=lambda item: item.priority):
            title = f"-> {obj.title}" if obj.parent_id else obj.title
            lines.append(
                f"| {obj.id} | {obj.phase.value} | {title} | {obj.status.value} | "
                f"{obj.priority} | {obj.owner or '-'} | {', '.join(obj.blocked_by) or '-'} |"
            )
        ready = self.ready()
        if ready:
            lines.append("")
            lines.append(f"Next: {ready[0].id} - {ready[0].title}")
        return "\n".join(lines)
