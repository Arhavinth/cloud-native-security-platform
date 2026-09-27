package main

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.privileged == true

    msg := sprintf(
        "Container %q must not run in privileged mode",
        [container.name]
    )
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    container.securityContext.allowPrivilegeEscalation == true

    msg := sprintf(
        "Container %q must not allow privilege escalation",
        [container.name]
    )
}

deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.resources.limits

    msg := sprintf(
        "Container %q must define resource limits",
        [container.name]
    )
}
deny contains msg if {
    input.kind == "Deployment"
    container := input.spec.template.spec.containers[_]
    not container.securityContext.runAsNonRoot

    msg := sprintf(
        "Container %q must run as non-root",
        [container.name]
    )
}