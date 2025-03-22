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

```zed
definition namespace {
    relation member: organization
    relation metadata: namespace
}

definition organization {
    relation member: role
    relation parent_namespace: namespace
    relation metadata: organization
}

definition user {
    relation primary_role: role
}

definition role {
    relation member: user | role#member
    relation parent_organization: organization
    relation parent_role: role
    relation metadata: role

    // Direct permission relationships
    relation can_call_method: method
    relation can_call_service: service
    relation can_view_component: ui_component
}

definition service {
    relation contains: method
    relation caller: user | role | role#member
    relation metadata: service
    permission access = caller
}

definition method {
    relation parent_service: service
    relation caller: user | role#member
    relation metadata: method
    permission access = caller + parent_service->access
}

definition ui_component {
    relation viewer: user | role#member
    relation metadata: ui_component
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

#### Setting up SpiceDB with PostgreSQL

1. Make sure you have PostgreSQL running and create a database named `spicedb`:
   ```bash
   psql -h localhost -U postgres -c "CREATE DATABASE spicedb;"
   ```

2. Run the database migration to set up the SpiceDB schema:
   ```bash
   docker run --rm \
     -e SPICEDB_DATASTORE_ENGINE=postgres \
     -e SPICEDB_DATASTORE_CONN_URI="postgresql://postgres:password@host.docker.internal:5432/spicedb?sslmode=disable" \
     authzed/spicedb:latest datastore migrate head
   ```

3. Start SpiceDB with PostgreSQL as the backend:
   ```bash
   docker run -p 50051:50051 \
     --name spicedb \
     -e SPICEDB_DATASTORE_ENGINE=postgres \
     -e SPICEDB_DATASTORE_CONN_URI="postgresql://postgres:password@host.docker.internal:5432/spicedb?sslmode=disable" \
     -e SPICEDB_GRPC_PRESHARED_KEY="somerandomkeyhere" \
     authzed/spicedb:latest serve
   ```

   > **Note:** Replace `password` with your actual PostgreSQL password. For macOS/Windows, use `host.docker.internal` to connect to the host machine's PostgreSQL. For Linux, you may need to use `--network=host` or the host's actual IP address.

4. Run the example application:
   ```bash
   go run main.go
   ```

#### Alternative: Using Docker Compose

For a more production-ready setup, you can use Docker Compose to run both PostgreSQL and SpiceDB:

```yaml
version: '3'

services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: spicedb
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5
    command: >
      postgres
      -c track_commit_timestamp=on

  spicedb-migrate:
    image: authzed/spicedb:latest
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      - SPICEDB_DATASTORE_ENGINE=postgres
      - SPICEDB_DATASTORE_CONN_URI=postgresql://postgres:postgres@postgres:5432/spicedb?sslmode=disable
    command: datastore migrate head
    restart: on-failure

  spicedb:
    image: authzed/spicedb:latest
    depends_on:
      spicedb-migrate:
        condition: service_completed_successfully
    ports:
      - "50051:50051"
    environment:
      - SPICEDB_DATASTORE_ENGINE=postgres
      - SPICEDB_DATASTORE_CONN_URI=postgresql://postgres:postgres@postgres:5432/spicedb?sslmode=disable
      - SPICEDB_GRPC_PRESHARED_KEY=somerandomkeyhere
    command: serve

volumes:
  postgres_data:
```

Save this as `docker-compose.yml` and run:

```bash
docker-compose up -d
```

## Implementation Details

### Metadata Relations

The schema uses self-referential metadata relations for each entity type. These are used to:

1. Mark an object's existence in SpiceDB (since SpiceDB creates objects implicitly)
2. Store additional information about the objects
3. Allow for listing all objects of a specific type

```zed
relation metadata: namespace  // Self-referential relation
```

### Bidirectional Relationships

The implementation maintains bidirectional relationships to ensure data integrity:

- When a role is granted access to a method, the role is also added as a caller to the method
- When a role is granted access to a service, the role is also added as a caller to the service
- When a role is granted access to a UI component, the role is also added as a viewer to the component

### Permission Inheritance

Method permissions can be inherited from service permissions:

- Method access = direct caller OR access through parent service
- This allows for granting access to all methods in a service with a single operation

## Error Handling

The implementation includes robust error handling for common scenarios:

- Attempting to access non-existent resources
- Deleting namespaces that contain organizations
- Managing relationships between non-existent objects
- Handling role transfers and permission revocation

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
- `CreateUIComponent(ctx, componentID)`: Creates a new UI component
- `DeleteUIComponent(ctx, componentID)`: Deletes a UI component
- `ListAllUIComponents(ctx)`: Lists all UI components

### Batch Operations

- `GrantServiceAndMethodsAccessToRole(ctx, roleID, serviceID)`: Grants service and method access
- `GrantUIComponentsAccessToRole(ctx, roleID, componentIDs)`: Grants access to multiple UI components
- `BatchCheckUIComponentAccess(ctx, userID, componentIDs)`: Checks access to multiple UI components
- `BatchCheckMethodAccess(ctx, userID, methodIDs)`: Checks access to multiple methods

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
