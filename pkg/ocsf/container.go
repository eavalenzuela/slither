package ocsf

import "fmt"

// ContainerLifecycle (OCSF class_uid 6000).
// Emitted when containerd/docker/runc-managed containers are created, started,
// stopped, destroyed, or have images pulled.
type ContainerLifecycle struct {
	Metadata    Metadata            `json:"metadata"`
	ClassUID    ClassID             `json:"class_uid"`
	ClassName   string              `json:"class_name"`
	ActivityID  ContainerActivityID `json:"activity_id"`
	TypeUID     uint64              `json:"type_uid"`
	Severity    Severity            `json:"severity_id"`
	SeverityStr string              `json:"severity,omitempty"`
	Time        TimeOCSF            `json:"time"`
	Device      Device              `json:"device"`
	Actor       Actor               `json:"actor"`
	Container   Container           `json:"container"`
}

type ContainerActivityID uint8

const (
	ContainerActivityUnknown ContainerActivityID = 0
	ContainerActivityCreate  ContainerActivityID = 1
	ContainerActivityStart   ContainerActivityID = 2
	ContainerActivityStop    ContainerActivityID = 3
	ContainerActivityDestroy ContainerActivityID = 4
	ContainerActivityPull    ContainerActivityID = 5
	ContainerActivityOther   ContainerActivityID = 99
)

type Container struct {
	UID                string   `json:"uid,omitempty"` // container id
	Name               string   `json:"name,omitempty"`
	Image              Image    `json:"image"`
	Runtime            string   `json:"runtime,omitempty"` // docker, containerd, cri-o, podman, lxc, nspawn
	Network            string   `json:"network_driver,omitempty"`
	OrchestratorLabels []string `json:"orchestrator,omitempty"`
	// CgroupPath is the container's cgroup, relative to the hierarchy
	// root, and CgroupID its cgroup v2 id — what the agent actually
	// observed; the runtime name and container id are derived from the
	// path. slither extensions.
	CgroupPath string `json:"x_cgroup_path,omitempty"`
	CgroupID   uint64 `json:"x_cgroup_id,omitempty"`
}

type Image struct {
	Name   string `json:"name,omitempty"`
	UID    string `json:"uid,omitempty"` // image id
	Tag    string `json:"tag,omitempty"`
	Digest string `json:"hashes.sha256,omitempty"`
}

func (c *ContainerLifecycle) ClassID() ClassID { return ClassContainerLifecycle }

func (c *ContainerLifecycle) Validate() error {
	if c.ClassUID != ClassContainerLifecycle {
		return fmt.Errorf("%w: class_uid %d != %d", ErrInvalidEvent, c.ClassUID, ClassContainerLifecycle)
	}
	if c.ActivityID == ContainerActivityUnknown {
		return fmt.Errorf("%w: activity_id required", ErrInvalidEvent)
	}
	if c.Time == 0 {
		return fmt.Errorf("%w: time required", ErrInvalidEvent)
	}
	if c.Container.UID == "" && c.Container.Name == "" {
		return fmt.Errorf("%w: container.uid or container.name required", ErrInvalidEvent)
	}
	return nil
}
