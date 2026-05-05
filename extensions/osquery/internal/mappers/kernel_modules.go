package mappers

import (
	"github.com/t3rmit3/slither/pkg/ocsf"
)

// KernelModules maps osquery's kernel_modules inventory table. Each
// loaded LKM becomes one OCSF KernelActivity{KernelActivityCreate} —
// "create" reads as "loaded into the kernel" rather than literal file
// creation, matching OCSF 1.3 KernelActivity semantics.
//
// Schema reference (osquery 5.x):
//
//	name, size, used_by, status, address.
//
// status is normally "Live"; we surface it via Severity bumping to
// SeverityLow for non-Live (loading / unloading) so rule authors can
// pick out transient states cheaply.
func KernelModules(row Row) (ocsf.Event, error) {
	if err := requireField("name", row["name"]); err != nil {
		return nil, err
	}
	severity := ocsf.SeverityInformational
	if status := row["status"]; status != "" && status != "Live" {
		severity = ocsf.SeverityLow
	}
	ev := &ocsf.KernelActivity{
		ClassUID:   ocsf.ClassKernelActivity,
		ClassName:  ocsf.ClassKernelActivity.String(),
		ActivityID: ocsf.KernelActivityCreate,
		Severity:   severity,
		Kernel: ocsf.KernelObject{
			Name: row["name"],
			Type: "Module",
		},
	}
	return ev, nil
}
