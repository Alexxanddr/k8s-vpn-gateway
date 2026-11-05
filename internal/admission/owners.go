package admission

import (
	"fmt"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ownerSelection(namespace string, owner meta.OwnerReference) (bool, error) {
	var rs object
	if err := apiRequest("GET", "/apis/apps/v1/namespaces/"+namespace+"/replicasets/"+owner.Name, nil, &rs); err != nil {
		return false, err
	}
	if rs.Metadata.UID != owner.UID {
		return false, fmt.Errorf("ReplicaSet owner UID mismatch")
	}
	if rs.Spec.Template.Metadata.Annotations[Annotation] != "" || rs.Spec.Template.Metadata.Annotations[Selection] != "" {
		return selected(rs.Spec.Template.Metadata.Annotations)
	}
	for _, parent := range rs.Metadata.OwnerReferences {
		if parent.Kind != "Deployment" || parent.Controller == nil || !*parent.Controller {
			continue
		}
		var deployment object
		if err := apiRequest("GET", "/apis/apps/v1/namespaces/"+namespace+"/deployments/"+parent.Name, nil, &deployment); err != nil {
			return false, err
		}
		if deployment.Metadata.UID != parent.UID {
			return false, fmt.Errorf("Deployment owner UID mismatch")
		}
		value, _, err := annotation(deployment.Metadata.Annotations, Annotation)
		if err != nil {
			return false, err
		}
		if explicit, ok, err := annotation(deployment.Spec.Template.Metadata.Annotations, Annotation); err != nil {
			return false, err
		} else if ok {
			value = explicit
		}
		return value == "true", nil
	}
	return false, nil
}
