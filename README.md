# SpiceDB Role-Based Access Control System

This repository contains a Go implementation of a role-based access control (RBAC) system using SpiceDB as the authorization backend. The system implements a hierarchical permission model with namespaces, organizations, roles, services, methods, and UI components.

## System Architecture

The permission system implements the following hierarchy:

```
Namespace → Organization → Role → User
```

And the following permission relationships:

```
Role ↔ Service
Role ↔ Method
Role ↔ UI Component
```

### Core Components

1. **Schema Definition**: The permission model is defined in a Spice schema that establishes the relationships between entities.

2. **PermissionManager**: A Go client that provides methods for managing users, roles, services, and permissions in SpiceDB.

3. **Example Application**: A sample application that demonstrates the usage of the permission system in different scenarios.

## Schema Overview

The permission system uses the following schema:

```
definition namespace {
    relation member: organization
}

definition organization {
    relation member: role
    relation parent_namespace: namespace
}

definition user {}

definition role {
    relation member: user | role#member
    relation parent_organization: organization
    relation parent_role: role

    // Direct permission relationships
    relation can_call_method: method
    relation can_call_service: service
    relation can_view_component: ui_component
}

definition service {
    relation contains: method
    relation caller: user | role#member
    permission access = caller
}

definition method {
    relation parent_service: service
    relation caller: user | role#member
    permission access = caller + parent_service->access
}

definition ui_component {
    relation viewer: user | role#member
    permission view = viewer
}
```

## Key Features

- **Multi-tenant support**: Organize permissions across different namespaces and organizations
- **Role-based access control**: Users are assigned roles that determine their permissions
- **Fine-grained access control**: Permissions can be granted at service or method level
- **UI component permissions**: Control which UI elements users can see
- **Bidirectional relationship maintenance**: Ensures data integrity in the permission system
- **Bulk operations**: Efficiently manage permissions for multiple entities
- **Permission checks**: Verify user access to services, methods, and UI components

## Usage Examples

### Setting Up a Multi-Tenant Environment

```go
// Create namespaces for different tenants
pm.CreateNamespace(ctx, "tenant1")
pm.CreateNamespace(ctx, "tenant2")

// Create organizations within namespaces
pm.CreateOrganizationInNamespace(ctx, "org1", "tenant1")
pm.CreateOrganizationInNamespace(ctx, "org2", "tenant2")

// Create roles within organizations
pm.CreateRole(ctx, "admin", "org1")
pm.CreateRole(ctx, "user", "org1")
```

### Managing User Roles

```go
// Assign a role to a user
pm.AssignRoleToUser(ctx, "user@example.com", "admin")

// Get a user's current role
role, err := pm.GetUserRole(ctx, "user@example.com")

// List all users with a specific role
users, err := pm.ListUsersWithRole(ctx, "admin")

// Remove a user's role
pm.RemoveUserRole(ctx, "user@example.com")
```

### Granting and Checking Permissions

```go
// Grant service access to a role
pm.GrantServiceAccessToRole(ctx, "admin", "UserService")

// Grant method access to a role
pm.GrantMethodAccessToRole(ctx, "admin", "/UserService/CreateUser")

// Grant UI component access to a role
pm.GrantUIComponentAccessToRole(ctx, "admin", "user_management_panel")

// Check if a user has access to a method
hasAccess, err := pm.CheckMethodAccess(ctx, "user@example.com", "/UserService/CreateUser")

// Check if a user can view a UI component
canView, err := pm.CheckUIComponentAccess(ctx, "user@example.com", "user_management_panel")
```

### Batch Operations

```go
// Grant access to a service and all its methods in one operation
pm.GrantServiceAndMethodsAccessToRole(ctx, "admin", "UserService")

// Grant access to multiple UI components
pm.GrantUIComponentsAccessToRole(ctx, "admin", []string{"dashboard", "reports", "settings"})

// Check access to multiple methods in one call
accessMap, err := pm.BatchCheckMethodAccess(ctx, "user@example.com", 
    []string{"/Service1/Method1", "/Service2/Method2"})
```

## Getting Started

### Prerequisites

- Go 1.18 or later
- SpiceDB running locally or in a remote environment
- Access token for SpiceDB

### Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   go mod tidy
   ```

### Running the Example

1. Start SpiceDB (using Docker or another method)
2. Set your SpiceDB token as an environment variable:
   ```bash
   export SPICEDB_TOKEN=your_token_here
   ```
3. Run the example application:
   ```bash
   go run main.go
   ```

## API Reference

The `PermissionManager` provides methods for managing all aspects of the permission system:

### User Role Management

- `AssignRoleToUser(ctx, userID, roleID)`: Assigns a role to a user
- `RemoveUserRole(ctx, userID)`: Removes a user's role
- `GetUserRole(ctx, userID)`: Gets a user's current role
- `ListUsersWithRole(ctx, roleID)`: Lists all users with a specific role

### Role Management

- `CreateRole(ctx, roleID, organizationID)`: Creates a new role in an organization
- `DeleteRole(ctx, roleID)`: Deletes a role
- `GetRoleOrganization(ctx, roleID)`: Gets the organization a role belongs to
- `ListOrganizationRoles(ctx, organizationID)`: Lists all roles in an organization

### Permission Management

- `GrantMethodAccessToRole(ctx, roleID, methodID)`: Grants a role access to a method
- `RevokeMethodAccessFromRole(ctx, roleID, methodID)`: Revokes method access
- `GrantServiceAccessToRole(ctx, roleID, serviceID)`: Grants a role access to a service
- `RevokeServiceAccessFromRole(ctx, roleID, serviceID)`: Revokes service access
- `GrantUIComponentAccessToRole(ctx, roleID, componentID)`: Grants UI component access
- `RevokeUIComponentAccessFromRole(ctx, roleID, componentID)`: Revokes UI component access

### Permission Checks

- `CheckMethodAccess(ctx, userID, methodID)`: Checks if a user can access a method
- `CheckServiceAccess(ctx, userID, serviceID)`: Checks if a user can access a service
- `CheckUIComponentAccess(ctx, userID, componentID)`: Checks if a user can view a UI component

### Entity Management

- `CreateNamespace(ctx, namespaceID)`: Creates a new namespace
- `DeleteNamespace(ctx, namespaceID)`: Deletes a namespace
- `ListNamespaces(ctx)`: Lists all namespaces
- `CreateOrganizationInNamespace(ctx, organizationID, namespaceID)`: Creates an organization
- `ListNamespaceOrganizations(ctx, namespaceID)`: Lists organizations in a namespace
- `CreateService(ctx, serviceID)`: Creates a new service
- `DeleteService(ctx, serviceID)`: Deletes a service
- `ListAllServices(ctx)`: Lists all services
- `RegisterMethod(ctx, methodID, serviceID)`: Registers a method with a service
- `ListServiceMethods(ctx, serviceID)`: Lists all methods in a service
- `CreateUI