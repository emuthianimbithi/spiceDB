package authz

import (
	"context"
	"fmt"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	authzed "github.com/authzed/authzed-go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PermissionManager struct {
	Client *authzed.Client
}

func NewPermissionManager(endpoint, token string) (*PermissionManager, error) {
	// For local development with insecure connection
	client, err := authzed.NewClient(
		endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpcutil.WithInsecureBearerToken(token),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create SpiceDB client: %w", err)
	}

	return &PermissionManager{Client: client}, nil
}

// ==================== User Role Management ====================

// AssignRoleToUser assigns a role to a user and removes any previous role
func (p *PermissionManager) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	// First, get the current role if any
	currentRole, err := p.GetUserRole(ctx, userID)
	if err != nil && err.Error() != "user does not have a role" {
		return fmt.Errorf("failed to get current user role: %w", err)
	}

	// Prepare updates
	var updates []*pb.RelationshipUpdate

	// Skip removing the current role if it's the same as the new role
	if currentRole == roleID {
		// User already has this role, nothing to do
		return nil
	}

	// If user has a current role, remove it
	if currentRole != "" {
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_DELETE,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "user",
					ObjectId:   userID,
				},
				Relation: "primary_role",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   currentRole,
					},
				},
			},
		})
	}

	// Add the new role
	updates = append(updates, &pb.RelationshipUpdate{
		Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
		Relationship: &pb.Relationship{
			Resource: &pb.ObjectReference{
				ObjectType: "user",
				ObjectId:   userID,
			},
			Relation: "primary_role",
			Subject: &pb.SubjectReference{
				Object: &pb.ObjectReference{
					ObjectType: "role",
					ObjectId:   roleID,
				},
			},
		},
	})

	// Write all updates in a single batch
	_, err = p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: updates,
	})

	if err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}
	return nil
}

// RemoveUserRole removes a user's role
func (p *PermissionManager) RemoveUserRole(ctx context.Context, userID string) error {
	// Get the current role to make sure it exists
	currentRole, err := p.GetUserRole(ctx, userID)
	if err != nil {
		if isNotFoundError(err) {
			// User doesn't have a role, nothing to do
			return nil
		}
		return fmt.Errorf("failed to get current user role: %w", err)
	}

	// Remove the role
	_, err = p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "user",
						ObjectId:   userID,
					},
					Relation: "primary_role",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   currentRole,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to remove user role: %w", err)
	}
	return nil
}

// GetUserRole gets a user's current role
func (p *PermissionManager) GetUserRole(ctx context.Context, userID string) (string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "user",
			ObjectId:   userID,
		},
		Permission:        "primary_role",
		SubjectObjectType: "role",
	})

	if err != nil {
		return "", fmt.Errorf("failed to lookup user role: %w", err)
	}

	result, err := resp.Recv()
	if err != nil {
		if err.Error() == "EOF" {
			return "", fmt.Errorf("user does not have a role")
		}
		return "", fmt.Errorf("error reading stream: %w", err)
	}

	roleID := result.Subject.SubjectObjectId

	// Check if there's more than one result, which shouldn't happen
	_, err = resp.Recv()
	if err == nil {
		return "", fmt.Errorf("user has multiple roles, schema inconsistency")
	}

	return roleID, nil
}

// ListUsersWithRole lists all users with a specific role
func (p *PermissionManager) ListUsersWithRole(ctx context.Context, roleID string) ([]string, error) {
	resp, err := p.Client.LookupResources(ctx, &pb.LookupResourcesRequest{
		ResourceObjectType: "user",
		Permission:         "primary_role",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "role",
				ObjectId:   roleID,
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup users with role: %w", err)
	}

	var users []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		users = append(users, result.ResourceObjectId)
	}

	return users, nil
}

// ==================== Role Management ====================

// CreateRole creates a new role in an organization
func (p *PermissionManager) CreateRole(ctx context.Context, roleID, organizationID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "parent_organization",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "organization",
							ObjectId:   organizationID,
						},
					},
				},
			},
			// Also add role as member of organization
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "organization",
						ObjectId:   organizationID,
					},
					Relation: "member",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

// DeleteRole deletes a role and removes all related permissions
// Note: This will leave users without a role if they had this role
func (p *PermissionManager) DeleteRole(ctx context.Context, roleID string) error {
	// First get the organization this role belongs to
	orgID, err := p.GetRoleOrganization(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role organization: %w", err)
	}

	// Prepare updates
	updates := []*pb.RelationshipUpdate{
		// Remove role from organization
		{
			Operation: pb.RelationshipUpdate_OPERATION_DELETE,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "organization",
					ObjectId:   orgID,
				},
				Relation: "member",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
				},
			},
		},
		// Remove organization from role
		{
			Operation: pb.RelationshipUpdate_OPERATION_DELETE,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "role",
					ObjectId:   roleID,
				},
				Relation: "parent_organization",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "organization",
						ObjectId:   orgID,
					},
				},
			},
		},
	}

	// Delete the relationships
	_, err = p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: updates,
	})

	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	return nil
}

// GetRoleOrganization gets the organization a role belongs to
func (p *PermissionManager) GetRoleOrganization(ctx context.Context, roleID string) (string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "role",
			ObjectId:   roleID,
		},
		Permission:        "parent_organization",
		SubjectObjectType: "organization",
	})

	if err != nil {
		return "", fmt.Errorf("failed to lookup role organization: %w", err)
	}

	result, err := resp.Recv()
	if err != nil {
		if err.Error() == "EOF" {
			return "", fmt.Errorf("role does not belong to any organization")
		}
		return "", fmt.Errorf("error reading stream: %w", err)
	}

	organizationID := result.Subject.SubjectObjectId

	// Check if there's more than one result, which shouldn't happen
	_, err = resp.Recv()
	if err == nil {
		return "", fmt.Errorf("role belongs to multiple organizations, schema inconsistency")
	}

	return organizationID, nil
}

// ListOrganizationRoles lists all roles in an organization
func (p *PermissionManager) ListOrganizationRoles(ctx context.Context, organizationID string) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "organization",
			ObjectId:   organizationID,
		},
		Permission:        "member",
		SubjectObjectType: "role",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup organization roles: %w", err)
	}

	var roles []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		roles = append(roles, result.Subject.SubjectObjectId)
	}

	return roles, nil
}

// ==================== Role Permission Management ====================

// GrantMethodAccessToRole grants a role access to a method
func (p *PermissionManager) GrantMethodAccessToRole(ctx context.Context, roleID, methodID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "can_call_method",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "method",
							ObjectId:   methodID,
						},
					},
				},
			},
			// Also add role as caller to method
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "method",
						ObjectId:   methodID,
					},
					Relation: "caller",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
						OptionalRelation: "member",
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to grant method access to role: %w", err)
	}
	return nil
}

// RevokeMethodAccessFromRole revokes a role's access to a method
func (p *PermissionManager) RevokeMethodAccessFromRole(ctx context.Context, roleID, methodID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "can_call_method",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "method",
							ObjectId:   methodID,
						},
					},
				},
			},
			// Also remove role as caller from method
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "method",
						ObjectId:   methodID,
					},
					Relation: "caller",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
						OptionalRelation: "member",
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to revoke method access from role: %w", err)
	}
	return nil
}

// GrantServiceAccessToRole grants a role access to a service
func (p *PermissionManager) GrantServiceAccessToRole(ctx context.Context, roleID, serviceID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "can_call_service",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "service",
							ObjectId:   serviceID,
						},
					},
				},
			},
			// Also add role as caller to service
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "service",
						ObjectId:   serviceID,
					},
					Relation: "caller",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to grant service access to role: %w", err)
	}
	return nil
}

// RevokeServiceAccessFromRole revokes a role's access to a service
func (p *PermissionManager) RevokeServiceAccessFromRole(ctx context.Context, roleID, serviceID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "can_call_service",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "service",
							ObjectId:   serviceID,
						},
					},
				},
			},
			// Also remove role as caller from service
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "service",
						ObjectId:   serviceID,
					},
					Relation: "caller",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
						OptionalRelation: "member",
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to revoke service access from role: %w", err)
	}
	return nil
}

// GrantUIComponentAccessToRole grants a role access to view a UI component
func (p *PermissionManager) GrantUIComponentAccessToRole(ctx context.Context, roleID, componentID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "can_view_component",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "ui_component",
							ObjectId:   componentID,
						},
					},
				},
			},
			// Also add role as viewer to UI component
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "ui_component",
						ObjectId:   componentID,
					},
					Relation: "viewer",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
						OptionalRelation: "member",
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to grant UI component access to role: %w", err)
	}
	return nil
}

// RevokeUIComponentAccessFromRole revokes a role's access to view a UI component
func (p *PermissionManager) RevokeUIComponentAccessFromRole(ctx context.Context, roleID, componentID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					Relation: "can_view_component",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "ui_component",
							ObjectId:   componentID,
						},
					},
				},
			},
			// Also remove role as viewer from UI component
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "ui_component",
						ObjectId:   componentID,
					},
					Relation: "viewer",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "role",
							ObjectId:   roleID,
						},
						OptionalRelation: "member",
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to revoke UI component access from role: %w", err)
	}
	return nil
}

// ==================== Permission Checks ====================

// CheckMethodAccess checks if a user can access a specific method
func (p *PermissionManager) CheckMethodAccess(ctx context.Context, userID, methodID string) (bool, error) {
	resp, err := p.Client.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "method",
			ObjectId:   methodID,
		},
		Permission: "access",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "user",
				ObjectId:   userID,
			},
		},
	})

	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check method access: %w", err)
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// CheckUIComponentAccess checks if a user can view a specific UI component
func (p *PermissionManager) CheckUIComponentAccess(ctx context.Context, userID, componentID string) (bool, error) {
	resp, err := p.Client.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "ui_component",
			ObjectId:   componentID,
		},
		Permission: "view",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "user",
				ObjectId:   userID,
			},
		},
	})

	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check UI component access: %w", err)
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// ==================== Helpers ====================

// isNotFoundError checks if an error is a "not found" error
func isNotFoundError(err error) bool {
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.NotFound
	}
	return false
}

// ListRoleMethods lists all methods a role can access
func (p *PermissionManager) ListRoleMethods(ctx context.Context, roleID string) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "role",
			ObjectId:   roleID,
		},
		Permission:        "can_call_method",
		SubjectObjectType: "method",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup role methods: %w", err)
	}

	var methods []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		methods = append(methods, result.Subject.SubjectObjectId)
	}

	return methods, nil
}

// ListRoleServices lists all services a role can access
func (p *PermissionManager) ListRoleServices(ctx context.Context, roleID string) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "role",
			ObjectId:   roleID,
		},
		Permission:        "can_call_service",
		SubjectObjectType: "service",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup role services: %w", err)
	}

	var services []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		services = append(services, result.Subject.SubjectObjectId)
	}

	return services, nil
}

// ListRoleUIComponents lists all UI components a role can view
func (p *PermissionManager) ListRoleUIComponents(ctx context.Context, roleID string) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "role",
			ObjectId:   roleID,
		},
		Permission:        "can_view_component",
		SubjectObjectType: "ui_component",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup role UI components: %w", err)
	}

	var components []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		components = append(components, result.Subject.SubjectObjectId)
	}

	return components, nil
}

// ListServiceMethods lists all methods in a service
func (p *PermissionManager) ListServiceMethods(ctx context.Context, serviceID string) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "service",
			ObjectId:   serviceID,
		},
		Permission:        "contains",
		SubjectObjectType: "method",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup service methods: %w", err)
	}

	var methods []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		methods = append(methods, result.Subject.SubjectObjectId)
	}

	return methods, nil
}

// RegisterMethod registers a method with its parent service
func (p *PermissionManager) RegisterMethod(ctx context.Context, methodID, serviceID string) error {
	updates := []*pb.RelationshipUpdate{
		// Link method to service
		{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "method",
					ObjectId:   methodID,
				},
				Relation: "parent_service",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "service",
						ObjectId:   serviceID,
					},
				},
			},
		},
		// Add method to service's contains relation
		{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "service",
					ObjectId:   serviceID,
				},
				Relation: "contains",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "method",
						ObjectId:   methodID,
					},
				},
			},
		},
	}

	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: updates,
	})

	if err != nil {
		return fmt.Errorf("failed to register method: %w", err)
	}
	return nil
}

// CreateOrganizationInNamespace creates a new organization in a namespace
func (p *PermissionManager) CreateOrganizationInNamespace(ctx context.Context, organizationID, namespaceID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace",
						ObjectId:   namespaceID,
					},
					Relation: "member",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "organization",
							ObjectId:   organizationID,
						},
					},
				},
			},
			// Set parent_namespace on organization
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "organization",
						ObjectId:   organizationID,
					},
					Relation: "parent_namespace",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace",
							ObjectId:   namespaceID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create organization in namespace: %w", err)
	}
	return nil
}

// GrantServiceAndMethodsAccessToRole grants a role access to a service and all its methods
func (p *PermissionManager) GrantServiceAndMethodsAccessToRole(ctx context.Context, roleID, serviceID string) error {
	// First grant access to the service
	err := p.GrantServiceAccessToRole(ctx, roleID, serviceID)
	if err != nil {
		return err
	}

	// Get all methods in the service
	methods, err := p.ListServiceMethods(ctx, serviceID)
	if err != nil {
		return fmt.Errorf("failed to list service methods: %w", err)
	}

	// Grant access to each method
	updates := make([]*pb.RelationshipUpdate, 0, len(methods)*2)
	for _, methodID := range methods {
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "role",
					ObjectId:   roleID,
				},
				Relation: "can_call_method",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "method",
						ObjectId:   methodID,
					},
				},
			},
		})
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "method",
					ObjectId:   methodID,
				},
				Relation: "caller",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					OptionalRelation: "member",
				},
			},
		})
	}

	// Write all updates in a single batch
	if len(updates) > 0 {
		_, err = p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
			Updates: updates,
		})
		if err != nil {
			return fmt.Errorf("failed to grant methods access to role: %w", err)
		}
	}

	return nil
}

// CreateNamespace creates a new namespace
func (p *PermissionManager) CreateNamespace(ctx context.Context, namespaceID string) error {
	// Namespaces don't require explicit creation in SpiceDB since objects are implicitly created
	// when relationships involving them are created. However, we can add a fake relationship
	// to ensure the namespace exists in the system.

	// Add a metadata relationship to mark the namespace as created
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace",
						ObjectId:   namespaceID,
					},
					// We use a self-referential relationship as a marker
					// This isn't specified in the schema but should be harmless
					Relation: "metadata",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace",
							ObjectId:   namespaceID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create namespace: %w", err)
	}
	return nil
}

// CreateService creates a new service
func (p *PermissionManager) CreateService(ctx context.Context, serviceID string) error {
	// Similar to namespaces, services don't require explicit creation,
	// but we can add a metadata relationship to mark it as created
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "service",
						ObjectId:   serviceID,
					},
					Relation: "metadata",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "service",
							ObjectId:   serviceID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	return nil
}

// CreateUIComponent creates a new UI component
func (p *PermissionManager) CreateUIComponent(ctx context.Context, componentID string) error {
	// Similar approach for UI components
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "ui_component",
						ObjectId:   componentID,
					},
					Relation: "metadata",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "ui_component",
							ObjectId:   componentID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to create UI component: %w", err)
	}
	return nil
}

// CheckServiceAccess checks if a user can access a specific service
func (p *PermissionManager) CheckServiceAccess(ctx context.Context, userID, serviceID string) (bool, error) {
	resp, err := p.Client.CheckPermission(ctx, &pb.CheckPermissionRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "service",
			ObjectId:   serviceID,
		},
		Permission: "access",
		Subject: &pb.SubjectReference{
			Object: &pb.ObjectReference{
				ObjectType: "user",
				ObjectId:   userID,
			},
		},
	})

	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check service access: %w", err)
	}

	return resp.Permissionship == pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION, nil
}

// GrantUIComponentsAccessToRole grants a role access to multiple UI components
func (p *PermissionManager) GrantUIComponentsAccessToRole(ctx context.Context, roleID string, componentIDs []string) error {
	if len(componentIDs) == 0 {
		return nil
	}

	updates := make([]*pb.RelationshipUpdate, 0, len(componentIDs)*2)
	for _, componentID := range componentIDs {
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "role",
					ObjectId:   roleID,
				},
				Relation: "can_view_component",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "ui_component",
						ObjectId:   componentID,
					},
				},
			},
		})
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_TOUCH,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "ui_component",
					ObjectId:   componentID,
				},
				Relation: "viewer",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "role",
						ObjectId:   roleID,
					},
					OptionalRelation: "member",
				},
			},
		})
	}

	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: updates,
	})

	if err != nil {
		return fmt.Errorf("failed to grant UI components access to role: %w", err)
	}
	return nil
}

// ListAllServices lists all services in the system
// Note: This only works if we've been consistent about adding metadata markers
func (p *PermissionManager) ListAllServices(ctx context.Context) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "service",
			ObjectId:   "*", // Wildcard to match all services
		},
		Permission:        "metadata",
		SubjectObjectType: "service",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list all services: %w", err)
	}

	var services []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		services = append(services, result.Subject.SubjectObjectId)
	}

	return services, nil
}

// ListAllUIComponents lists all UI components in the system
// Note: This only works if we've been consistent about adding metadata markers
func (p *PermissionManager) ListAllUIComponents(ctx context.Context) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "ui_component",
			ObjectId:   "*", // Wildcard to match all UI components
		},
		Permission:        "metadata",
		SubjectObjectType: "ui_component",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list all UI components: %w", err)
	}

	var components []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		components = append(components, result.Subject.SubjectObjectId)
	}

	return components, nil
}

// ListNamespaces lists all namespaces in the system
// Note: This only works if we've been consistent about adding metadata markers
func (p *PermissionManager) ListNamespaces(ctx context.Context) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "namespace",
			ObjectId:   "*", // Wildcard to match all namespaces
		},
		Permission:        "metadata",
		SubjectObjectType: "namespace",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to list all namespaces: %w", err)
	}

	var namespaces []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		namespaces = append(namespaces, result.Subject.SubjectObjectId)
	}

	return namespaces, nil
}

// Additional helper methods that might be useful

// DeleteService deletes a service and all its methods
func (p *PermissionManager) DeleteService(ctx context.Context, serviceID string) error {
	// First, get all methods for this service
	methods, err := p.ListServiceMethods(ctx, serviceID)
	if err != nil {
		return fmt.Errorf("failed to list service methods: %w", err)
	}

	// Prepare updates to remove method relationships
	updates := make([]*pb.RelationshipUpdate, 0, len(methods)*2+1)

	// Add update to remove the service metadata
	updates = append(updates, &pb.RelationshipUpdate{
		Operation: pb.RelationshipUpdate_OPERATION_DELETE,
		Relationship: &pb.Relationship{
			Resource: &pb.ObjectReference{
				ObjectType: "service",
				ObjectId:   serviceID,
			},
			Relation: "metadata",
			Subject: &pb.SubjectReference{
				Object: &pb.ObjectReference{
					ObjectType: "service",
					ObjectId:   serviceID,
				},
			},
		},
	})

	// For each method, remove its relationship with the service
	for _, methodID := range methods {
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_DELETE,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "method",
					ObjectId:   methodID,
				},
				Relation: "parent_service",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "service",
						ObjectId:   serviceID,
					},
				},
			},
		})
		updates = append(updates, &pb.RelationshipUpdate{
			Operation: pb.RelationshipUpdate_OPERATION_DELETE,
			Relationship: &pb.Relationship{
				Resource: &pb.ObjectReference{
					ObjectType: "service",
					ObjectId:   serviceID,
				},
				Relation: "contains",
				Subject: &pb.SubjectReference{
					Object: &pb.ObjectReference{
						ObjectType: "method",
						ObjectId:   methodID,
					},
				},
			},
		})
	}

	// Write all updates in a single batch
	_, err = p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: updates,
	})

	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	return nil
}

// DeleteUIComponent deletes a UI component
func (p *PermissionManager) DeleteUIComponent(ctx context.Context, componentID string) error {
	_, err := p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "ui_component",
						ObjectId:   componentID,
					},
					Relation: "metadata",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "ui_component",
							ObjectId:   componentID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to delete UI component: %w", err)
	}
	return nil
}

// DeleteNamespace deletes a namespace
func (p *PermissionManager) DeleteNamespace(ctx context.Context, namespaceID string) error {
	// First check if namespace has any organizations
	orgs, err := p.ListNamespaceOrganizations(ctx, namespaceID)
	if err != nil {
		return fmt.Errorf("failed to check if namespace has organizations: %w", err)
	}

	if len(orgs) > 0 {
		return fmt.Errorf("cannot delete namespace that contains organizations")
	}

	_, err = p.Client.WriteRelationships(ctx, &pb.WriteRelationshipsRequest{
		Updates: []*pb.RelationshipUpdate{
			{
				Operation: pb.RelationshipUpdate_OPERATION_DELETE,
				Relationship: &pb.Relationship{
					Resource: &pb.ObjectReference{
						ObjectType: "namespace",
						ObjectId:   namespaceID,
					},
					Relation: "metadata",
					Subject: &pb.SubjectReference{
						Object: &pb.ObjectReference{
							ObjectType: "namespace",
							ObjectId:   namespaceID,
						},
					},
				},
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to delete namespace: %w", err)
	}
	return nil
}

// BatchCheckUIComponentAccess checks access to multiple UI components for a user
func (p *PermissionManager) BatchCheckUIComponentAccess(ctx context.Context, userID string, componentIDs []string) (map[string]bool, error) {
	results := make(map[string]bool, len(componentIDs))

	// This could be optimized by using bulk APIs if SpiceDB supports them
	for _, componentID := range componentIDs {
		hasAccess, err := p.CheckUIComponentAccess(ctx, userID, componentID)
		if err != nil {
			return nil, fmt.Errorf("failed to check access for component %s: %w", componentID, err)
		}
		results[componentID] = hasAccess
	}

	return results, nil
}

// BatchCheckMethodAccess checks access to multiple methods for a user
func (p *PermissionManager) BatchCheckMethodAccess(ctx context.Context, userID string, methodIDs []string) (map[string]bool, error) {
	results := make(map[string]bool, len(methodIDs))

	// This could be optimized by using bulk APIs if SpiceDB supports them
	for _, methodID := range methodIDs {
		hasAccess, err := p.CheckMethodAccess(ctx, userID, methodID)
		if err != nil {
			return nil, fmt.Errorf("failed to check access for method %s: %w", methodID, err)
		}
		results[methodID] = hasAccess
	}

	return results, nil
}

// ListNamespaceOrganizations lists all organizations in a namespace
func (p *PermissionManager) ListNamespaceOrganizations(ctx context.Context, namespaceID string) ([]string, error) {
	resp, err := p.Client.LookupSubjects(ctx, &pb.LookupSubjectsRequest{
		Resource: &pb.ObjectReference{
			ObjectType: "namespace",
			ObjectId:   namespaceID,
		},
		Permission:        "member",
		SubjectObjectType: "organization",
	})

	if err != nil {
		return nil, fmt.Errorf("failed to lookup namespace organizations: %w", err)
	}

	var organizations []string
	for {
		result, err := resp.Recv()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("error reading stream: %w", err)
		}

		organizations = append(organizations, result.Subject.SubjectObjectId)
	}

	return organizations, nil
}
