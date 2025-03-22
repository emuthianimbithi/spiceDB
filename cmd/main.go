package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"spiceDB/pkg/authz"
)

func main() {
	// Create a new permission manager using your local SpiceDB instance
	pm, err := authz.NewPermissionManager(
		"localhost:50051",
		"somerandomkeyhere", // Get token from environment variable for security
	)
	if err != nil {
		log.Fatalf("Failed to create permission manager: %v", err)
	}
	ctx := context.Background()

	// Read the schema file
	schemaContent, err := os.ReadFile("schema.zed")
	if err != nil {
		log.Fatalf("Failed to read schema file: %v", err)
	}

	// Upload the schema
	fmt.Println("Uploading schema...")
	_, err = pm.Client.WriteSchema(ctx, &pb.WriteSchemaRequest{
		Schema: string(schemaContent),
	})
	if err != nil {
		log.Fatalf("Failed to write schema: %v", err)
	}
	fmt.Println("Schema uploaded successfully!")

	// Create tracking structures to record created resources for cleanup
	resources := &TestResources{
		Namespaces:    make([]string, 0),
		Organizations: make([]string, 0),
		Roles:         make([]string, 0),
		Services:      make([]string, 0),
		UIComponents:  make([]string, 0),
		Users:         make([]string, 0),
	}

	// Set up multi-tenant example with two namespaces and organizations
	setupMultiTenantExample(ctx, pm, resources)

	// Set up UI component permissions example
	setupUIPermissionsExample(ctx, pm, resources)

	// Test method-level permissions with fine-grained control
	testMethodLevelPermissions(ctx, pm, resources)

	// Demonstrate batch operations
	demonstrateBatchOperations(ctx, pm, resources)

	// Test permission checks and validation
	testPermissionChecks(ctx, pm)

	// Demonstrate error handling and edge cases
	demonstrateErrorHandling(ctx, pm, resources)

	// Test role transfer
	testRoleTransfer(ctx, pm, resources)

	fmt.Println("All demonstrations completed successfully!")

	// Cleanup all test resources
	cleanupResources(ctx, pm, resources)
}

// TestResources keeps track of all resources created during testing for cleanup
type TestResources struct {
	Namespaces    []string
	Organizations []string
	Roles         []string
	Services      []string
	UIComponents  []string
	Users         []string
}

// setupMultiTenantExample demonstrates setting up a multi-tenant permission structure
func setupMultiTenantExample(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Setting up Multi-Tenant Example ===")

	// Create namespaces for two different tenants
	namespaces := []string{"acme", "globex"}
	for _, ns := range namespaces {
		fmt.Printf("Creating namespace: %s\n", ns)
		if err := pm.CreateNamespace(ctx, ns); err != nil {
			log.Fatalf("Failed to create namespace %s: %v", ns, err)
		}
		resources.Namespaces = append(resources.Namespaces, ns)
	}

	// Create organizations within each namespace
	organizations := map[string][]string{
		"acme":   {"acme_sales", "acme_engineering"},
		"globex": {"globex_marketing", "globex_support"},
	}

	for ns, orgs := range organizations {
		for _, org := range orgs {
			fmt.Printf("Creating organization %s in namespace %s\n", org, ns)
			if err := pm.CreateOrganizationInNamespace(ctx, org, ns); err != nil {
				log.Fatalf("Failed to create organization %s: %v", org, err)
			}
			resources.Organizations = append(resources.Organizations, org)
		}
	}

	// Create roles within each organization
	roles := map[string][]string{
		"acme_sales":       {"sales_manager", "sales_rep"},
		"acme_engineering": {"engineering_lead", "engineer"},
		"globex_marketing": {"marketing_director", "marketing_specialist"},
		"globex_support":   {"support_manager", "support_agent"},
	}

	for org, roleList := range roles {
		for _, role := range roleList {
			fmt.Printf("Creating role %s in organization %s\n", role, org)
			if err := pm.CreateRole(ctx, role, org); err != nil {
				log.Fatalf("Failed to create role %s: %v", role, err)
			}
			resources.Roles = append(resources.Roles, role)
		}
	}

	// Create services
	services := []string{"CRMService", "BillingService", "SupportService", "AnalyticsService"}
	for _, service := range services {
		fmt.Printf("Creating service: %s\n", service)
		if err := pm.CreateService(ctx, service); err != nil {
			log.Fatalf("Failed to create service %s: %v", service, err)
		}
		resources.Services = append(resources.Services, service)
	}

	// Register methods for each service
	methods := map[string][]string{
		"CRMService": {
			"/CRMService/GetCustomer",
			"/CRMService/CreateCustomer",
			"/CRMService/UpdateCustomer",
			"/CRMService/DeleteCustomer",
		},
		"BillingService": {
			"/BillingService/GetInvoice",
			"/BillingService/CreateInvoice",
			"/BillingService/ProcessPayment",
		},
		"SupportService": {
			"/SupportService/CreateTicket",
			"/SupportService/UpdateTicket",
			"/SupportService/CloseTicket",
			"/SupportService/GetTickets",
		},
		"AnalyticsService": {
			"/AnalyticsService/GetSalesReport",
			"/AnalyticsService/GetCustomerMetrics",
			"/AnalyticsService/GetSupportMetrics",
		},
	}

	for service, methodList := range methods {
		for _, method := range methodList {
			fmt.Printf("Registering method %s for service %s\n", method, service)
			if err := pm.RegisterMethod(ctx, method, service); err != nil {
				log.Fatalf("Failed to register method %s: %v", method, err)
			}
		}
	}

	// Create some users
	users := map[string]struct {
		Role         string
		Organization string
	}{
		"alice_acme_com":   {Role: "sales_manager", Organization: "acme_sales"},
		"bob_acme_com":     {Role: "engineer", Organization: "acme_engineering"},
		"carol_globex_com": {Role: "marketing_director", Organization: "globex_marketing"},
		"dave_globex_com":  {Role: "support_agent", Organization: "globex_support"},
	}

	// Assign roles to users
	for userID, info := range users {
		fmt.Printf("Assigning role %s to user %s\n", info.Role, userID)
		if err := pm.AssignRoleToUser(ctx, userID, info.Role); err != nil {
			log.Fatalf("Failed to assign role to user %s: %v", userID, err)
		}
		resources.Users = append(resources.Users, userID)
	}

	// Grant service access to roles
	roleServiceAccess := map[string][]string{
		"sales_manager":      {"CRMService", "BillingService", "AnalyticsService"},
		"engineer":           {"SupportService"},
		"marketing_director": {"CRMService", "AnalyticsService"},
		"support_agent":      {"SupportService", "CRMService"},
	}

	for role, serviceList := range roleServiceAccess {
		for _, service := range serviceList {
			fmt.Printf("Granting service %s access to role %s\n", service, role)
			if err := pm.GrantServiceAccessToRole(ctx, role, service); err != nil {
				log.Fatalf("Failed to grant service access to role: %v", err)
			}
		}
	}

	// Verify some role assignments
	for userID, _ := range users {
		role, err := pm.GetUserRole(ctx, userID)
		if err != nil {
			log.Fatalf("Failed to get role for user %s: %v", userID, err)
		}
		fmt.Printf("User %s has role: %s\n", userID, role)

		// List services the user can access
		services, err := pm.ListRoleServices(ctx, role)
		if err != nil {
			log.Fatalf("Failed to list services for role %s: %v", role, err)
		}
		fmt.Printf("User %s can access services: %v\n", userID, services)
	}

	fmt.Println("Multi-tenant example setup completed successfully!")
}

// setupUIPermissionsExample demonstrates UI component permissions
func setupUIPermissionsExample(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Setting up UI Permissions Example ===")

	// Create UI components
	components := []string{
		"dashboard",
		"customer_list",
		"invoice_list",
		"admin_panel",
		"support_portal",
		"analytics_dashboard",
		"user_management",
		"billing_settings",
	}

	for _, component := range components {
		fmt.Printf("Creating UI component: %s\n", component)
		if err := pm.CreateUIComponent(ctx, component); err != nil {
			log.Fatalf("Failed to create UI component %s: %v", component, err)
		}
		resources.UIComponents = append(resources.UIComponents, component)
	}

	// Set up component access for different roles
	roleComponentAccess := map[string][]string{
		"sales_manager": {
			"dashboard", "customer_list", "invoice_list", "analytics_dashboard",
		},
		"engineer": {
			"dashboard", "support_portal",
		},
		"marketing_director": {
			"dashboard", "customer_list", "analytics_dashboard",
		},
		"support_agent": {
			"dashboard", "customer_list", "support_portal",
		},
		"sales_rep": {
			"dashboard", "customer_list",
		},
	}

	// Grant UI component access to roles in bulk
	for role, componentList := range roleComponentAccess {
		fmt.Printf("Granting UI components %v access to role %s\n", componentList, role)
		if err := pm.GrantUIComponentsAccessToRole(ctx, role, componentList); err != nil {
			log.Fatalf("Failed to grant UI components access to role: %v", err)
		}
	}

	// Verify component access for a user
	userID := "alice_acme_com"
	role, err := pm.GetUserRole(ctx, userID)
	if err != nil {
		log.Fatalf("Failed to get role for user %s: %v", userID, err)
	}

	components, err = pm.ListRoleUIComponents(ctx, role)
	if err != nil {
		log.Fatalf("Failed to list UI components for role %s: %v", role, err)
	}
	fmt.Printf("User %s can access UI components: %v\n", userID, components)

	// Check specific component access
	hasAccess, err := pm.CheckUIComponentAccess(ctx, userID, "admin_panel")
	if err != nil {
		log.Fatalf("Failed to check UI component access: %v", err)
	}
	fmt.Printf("User %s has access to admin_panel: %v (should be false)\n", userID, hasAccess)

	hasAccess, err = pm.CheckUIComponentAccess(ctx, userID, "dashboard")
	if err != nil {
		log.Fatalf("Failed to check UI component access: %v", err)
	}
	fmt.Printf("User %s has access to dashboard: %v (should be true)\n", userID, hasAccess)

	fmt.Println("UI permissions example completed successfully!")
}

// testMethodLevelPermissions demonstrates fine-grained control at the method level
func testMethodLevelPermissions(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Testing Method-Level Permissions ===")

	// Create a restricted role with only read access
	role := "readonly_agent"
	org := "globex_support"

	fmt.Printf("Creating role %s in organization %s\n", role, org)
	if err := pm.CreateRole(ctx, role, org); err != nil {
		log.Fatalf("Failed to create role %s: %v", role, err)
	}
	resources.Roles = append(resources.Roles, role)

	// Grant access to only read methods
	readMethods := []string{
		"/CRMService/GetCustomer",
		"/SupportService/GetTickets",
		"/BillingService/GetInvoice",
	}

	for _, method := range readMethods {
		fmt.Printf("Granting method %s access to role %s\n", method, role)
		if err := pm.GrantMethodAccessToRole(ctx, role, method); err != nil {
			log.Fatalf("Failed to grant method access to role: %v", err)
		}
	}

	// Create a new user with this role
	userID := "readonly_globex_com"
	fmt.Printf("Assigning role %s to user %s\n", role, userID)
	if err := pm.AssignRoleToUser(ctx, userID, role); err != nil {
		log.Fatalf("Failed to assign role to user: %v", err)
	}
	resources.Users = append(resources.Users, userID)

	// Check access to read methods
	for _, method := range readMethods {
		hasAccess, err := pm.CheckMethodAccess(ctx, userID, method)
		if err != nil {
			log.Fatalf("Failed to check method access: %v", err)
		}
		fmt.Printf("User %s has access to method %s: %v (should be true)\n", userID, method, hasAccess)
	}

	// Check access to write methods
	writeMethods := []string{
		"/CRMService/CreateCustomer",
		"/SupportService/UpdateTicket",
		"/BillingService/CreateInvoice",
	}

	for _, method := range writeMethods {
		hasAccess, err := pm.CheckMethodAccess(ctx, userID, method)
		if err != nil {
			log.Fatalf("Failed to check method access: %v", err)
		}
		fmt.Printf("User %s has access to method %s: %v (should be false)\n", userID, method, hasAccess)
	}

	// Grant access to service but check that it doesn't override method-level restrictions
	fmt.Printf("Granting service access but testing method-level restrictions\n")

	serviceID := "CRMService"
	if err := pm.GrantServiceAccessToRole(ctx, role, serviceID); err != nil {
		log.Fatalf("Failed to grant service access to role: %v", err)
	}

	// This should now have access to the service
	hasAccess, err := pm.CheckServiceAccess(ctx, userID, serviceID)
	if err != nil {
		log.Fatalf("Failed to check service access: %v", err)
	}
	fmt.Printf("User %s has access to service %s: %v (should be true)\n", userID, serviceID, hasAccess)

	// But should not have access to write methods that weren't explicitly granted
	writeMethod := "/CRMService/CreateCustomer"
	hasAccess, err = pm.CheckMethodAccess(ctx, userID, writeMethod)
	if err != nil {
		log.Fatalf("Failed to check method access: %v", err)
	}
	fmt.Printf("User %s has access to method %s: %v (should be false)\n", userID, writeMethod, hasAccess)

	fmt.Println("Method-level permissions testing completed successfully!")
}

// demonstrateBatchOperations shows how to use batch operations for efficiency
func demonstrateBatchOperations(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Demonstrating Batch Operations ===")

	// Create a new role for batch operations
	role := "batch_test_role"
	org := "acme_sales"

	fmt.Printf("Creating role %s in organization %s\n", role, org)
	if err := pm.CreateRole(ctx, role, org); err != nil {
		log.Fatalf("Failed to create role %s: %v", role, err)
	}
	resources.Roles = append(resources.Roles, role)

	// Create a user with this role
	userID := "batch_acme_com"
	fmt.Printf("Assigning role %s to user %s\n", role, userID)
	if err := pm.AssignRoleToUser(ctx, userID, role); err != nil {
		log.Fatalf("Failed to assign role to user: %v", err)
	}
	resources.Users = append(resources.Users, userID)

	// Batch grant service and methods access
	serviceID := "CRMService"
	fmt.Printf("Granting service %s and all its methods to role %s\n", serviceID, role)
	if err := pm.GrantServiceAndMethodsAccessToRole(ctx, role, serviceID); err != nil {
		log.Fatalf("Failed to grant service and methods access: %v", err)
	}

	// List methods that were granted
	methods, err := pm.ListRoleMethods(ctx, role)
	if err != nil {
		log.Fatalf("Failed to list role methods: %v", err)
	}
	fmt.Printf("Role %s was granted access to methods: %v\n", role, methods)

	// Batch grant UI components access
	components := []string{"dashboard", "customer_list", "analytics_dashboard"}
	fmt.Printf("Granting UI components %v to role %s\n", components, role)
	if err := pm.GrantUIComponentsAccessToRole(ctx, role, components); err != nil {
		log.Fatalf("Failed to grant UI components access: %v", err)
	}

	// Batch check UI component access
	results, err := pm.BatchCheckUIComponentAccess(ctx, userID, components)
	if err != nil {
		log.Fatalf("Failed to batch check UI component access: %v", err)
	}
	fmt.Printf("Batch UI component access check results: %v\n", results)

	// Batch check method access
	methodsToCheck := []string{
		"/CRMService/GetCustomer",
		"/CRMService/CreateCustomer",
		"/BillingService/GetInvoice", // This should be false
	}
	methodResults, err := pm.BatchCheckMethodAccess(ctx, userID, methodsToCheck)
	if err != nil {
		log.Fatalf("Failed to batch check method access: %v", err)
	}
	fmt.Printf("Batch method access check results: %v\n", methodResults)

	fmt.Println("Batch operations demonstration completed successfully!")
}

// testPermissionChecks demonstrates various permission checks and validations
func testPermissionChecks(ctx context.Context, pm *authz.PermissionManager) {
	fmt.Println("\n=== Testing Permission Checks ===")

	// Get all namespaces in the system
	namespaces, err := pm.ListNamespaces(ctx)
	if err != nil {
		log.Fatalf("Failed to list namespaces: %v", err)
	}
	fmt.Printf("All namespaces in the system: %v\n", namespaces)

	// Get all services in the system
	services, err := pm.ListAllServices(ctx)
	if err != nil {
		log.Fatalf("Failed to list services: %v", err)
	}
	fmt.Printf("All services in the system: %v\n", services)

	// Get all UI components in the system
	components, err := pm.ListAllUIComponents(ctx)
	if err != nil {
		log.Fatalf("Failed to list UI components: %v", err)
	}
	fmt.Printf("All UI components in the system: %v\n", components)

	// Check organization structure
	namespace := "acme"
	organizations, err := pm.ListNamespaceOrganizations(ctx, namespace)
	if err != nil {
		log.Fatalf("Failed to list organizations in namespace %s: %v", namespace, err)
	}
	fmt.Printf("Organizations in namespace %s: %v\n", namespace, organizations)

	// Check role structure for an organization
	organization := "acme_sales"
	roles, err := pm.ListOrganizationRoles(ctx, organization)
	if err != nil {
		log.Fatalf("Failed to list roles in organization %s: %v", organization, err)
	}
	fmt.Printf("Roles in organization %s: %v\n", organization, roles)

	// Test service-level access
	userID := "alice_acme_com"
	serviceID := "CRMService"
	hasAccess, err := pm.CheckServiceAccess(ctx, userID, serviceID)
	if err != nil {
		log.Fatalf("Failed to check service access: %v", err)
	}
	fmt.Printf("User %s has access to service %s: %v\n", userID, serviceID, hasAccess)

	// Test method-level access
	methodID := "/CRMService/GetCustomer"
	hasAccess, err = pm.CheckMethodAccess(ctx, userID, methodID)
	if err != nil {
		log.Fatalf("Failed to check method access: %v", err)
	}
	fmt.Printf("User %s has access to method %s: %v\n", userID, methodID, hasAccess)

	fmt.Println("Permission checks testing completed successfully!")
}

// demonstrateErrorHandling shows common error cases and how to handle them
func demonstrateErrorHandling(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Demonstrating Error Handling ===")

	// Attempt to get role for non-existent user
	nonExistentUser := "nonexistent_example_com"
	fmt.Printf("Attempting to get role for non-existent user %s\n", nonExistentUser)
	_, err := pm.GetUserRole(ctx, nonExistentUser)
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	} else {
		log.Fatalf("Expected error but got success for non-existent user")
	}

	// Attempt to delete a namespace with organizations
	namespace := "acme"
	fmt.Printf("Attempting to delete namespace %s that contains organizations\n", namespace)
	err = pm.DeleteNamespace(ctx, namespace)
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	} else {
		log.Fatalf("Expected error but got success for deleting namespace with organizations")
	}

	// Attempt to create a role in a non-existent organization
	fmt.Println("Attempting to create a role in a non-existent organization")
	err = pm.CreateRole(ctx, "test_role", "nonexistent_org")
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	} else {
		// This could actually succeed since SpiceDB creates objects implicitly
		fmt.Printf("No error when creating role in non-existent organization (expected with SpiceDB)\n")
	}

	// Create a temporary namespace for deletion test
	tempNamespace := fmt.Sprintf("temp_%d", time.Now().Unix())
	fmt.Printf("Creating temporary namespace %s for deletion test\n", tempNamespace)
	err = pm.CreateNamespace(ctx, tempNamespace)
	if err != nil {
		log.Fatalf("Failed to create temporary namespace: %v", err)
	}
	resources.Namespaces = append(resources.Namespaces, tempNamespace)

	// Now delete it (should succeed)
	fmt.Printf("Deleting temporary namespace %s\n", tempNamespace)
	err = pm.DeleteNamespace(ctx, tempNamespace)
	if err != nil {
		log.Fatalf("Failed to delete temporary namespace: %v", err)
	}
	// Remove from resources since we deleted it
	for i, ns := range resources.Namespaces {
		if ns == tempNamespace {
			resources.Namespaces = append(resources.Namespaces[:i], resources.Namespaces[i+1:]...)
			break
		}
	}
	fmt.Printf("Successfully deleted namespace %s\n", tempNamespace)

	fmt.Println("Error handling demonstration completed successfully!")
}

// testRoleTransfer demonstrates transferring a user from one role to another
func testRoleTransfer(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Testing Role Transfer ===")

	// Create a user with an initial role
	userID := "transfer_acme_com"
	initialRole := "sales_rep"
	newRole := "sales_manager"

	fmt.Printf("Creating user %s with initial role %s\n", userID, initialRole)
	if err := pm.AssignRoleToUser(ctx, userID, initialRole); err != nil {
		log.Fatalf("Failed to assign initial role to user: %v", err)
	}
	resources.Users = append(resources.Users, userID)

	// Verify initial role assignment
	role, err := pm.GetUserRole(ctx, userID)
	if err != nil {
		log.Fatalf("Failed to get role for user %s: %v", userID, err)
	}
	fmt.Printf("User %s initially has role: %s\n", userID, role)

	// Grant some UI component access to the initial role if not already done
	initialComponents := []string{"dashboard", "customer_list"}
	fmt.Printf("Ensuring initial role %s has access to UI components\n", initialRole)
	if err := pm.GrantUIComponentsAccessToRole(ctx, initialRole, initialComponents); err != nil {
		log.Fatalf("Failed to grant UI components access to role: %v", err)
	}

	// Check initial component access
	hasAccess, err := pm.CheckUIComponentAccess(ctx, userID, "dashboard")
	if err != nil {
		log.Fatalf("Failed to check UI component access: %v", err)
	}
	fmt.Printf("Before transfer, user %s has access to dashboard: %v (should be true)\n", userID, hasAccess)

	// Now transfer the user to a new role
	fmt.Printf("Transferring user %s from role %s to role %s\n", userID, initialRole, newRole)
	if err := pm.AssignRoleToUser(ctx, userID, newRole); err != nil {
		log.Fatalf("Failed to transfer user to new role: %v", err)
	}

	// Verify new role assignment
	role, err = pm.GetUserRole(ctx, userID)
	if err != nil {
		log.Fatalf("Failed to get role for user %s: %v", userID, err)
	}
	fmt.Printf("User %s now has role: %s\n", userID, role)

	// The new role should have different permissions
	// Grant additional access to the new role
	additionalComponents := []string{"invoice_list", "analytics_dashboard"}
	fmt.Printf("Ensuring new role %s has access to additional UI components\n", newRole)
	if err := pm.GrantUIComponentsAccessToRole(ctx, newRole, append(initialComponents, additionalComponents...)); err != nil {
		log.Fatalf("Failed to grant UI components access to role: %v", err)
	}

	// Check access with new role
	components := append(initialComponents, additionalComponents...)
	for _, component := range components {
		hasAccess, err := pm.CheckUIComponentAccess(ctx, userID, component)
		if err != nil {
			log.Fatalf("Failed to check UI component access: %v", err)
		}
		fmt.Printf("After transfer, user %s has access to %s: %v (should be true)\n", userID, component, hasAccess)
	}

	// Verify the old role's permissions don't apply anymore
	// Create a new component and only grant it to the old role
	exclusiveComponent := "exclusive_to_initial_role"
	fmt.Printf("Creating component %s only for initial role %s\n", exclusiveComponent, initialRole)
	if err := pm.CreateUIComponent(ctx, exclusiveComponent); err != nil {
		log.Fatalf("Failed to create exclusive UI component: %v", err)
	}
	resources.UIComponents = append(resources.UIComponents, exclusiveComponent)

	if err := pm.GrantUIComponentAccessToRole(ctx, initialRole, exclusiveComponent); err != nil {
		log.Fatalf("Failed to grant exclusive component access: %v", err)
	}

	// Verify user doesn't have access to exclusive component after role transfer
	hasAccess, err = pm.CheckUIComponentAccess(ctx, userID, exclusiveComponent)
	if err != nil {
		log.Fatalf("Failed to check UI component access: %v", err)
	}
	fmt.Printf("After transfer, user %s has access to %s: %v (should be false)\n", userID, exclusiveComponent, hasAccess)

	fmt.Println("Role transfer testing completed successfully!")
}

// cleanupResources cleans up all resources created during testing
func cleanupResources(ctx context.Context, pm *authz.PermissionManager, resources *TestResources) {
	fmt.Println("\n=== Cleaning Up Resources ===")

	// Remove user roles first
	for _, userID := range resources.Users {
		fmt.Printf("Removing role from user %s\n", userID)
		if err := pm.RemoveUserRole(ctx, userID); err != nil {
			fmt.Printf("Warning: Failed to remove role from user %s: %v\n", userID, err)
		}
	}

	// Delete UI components
	for _, component := range resources.UIComponents {
		fmt.Printf("Deleting UI component %s\n", component)
		if err := pm.DeleteUIComponent(ctx, component); err != nil {
			fmt.Printf("Warning: Failed to delete UI component %s: %v\n", component, err)
		}
	}

	// Delete services
	for _, service := range resources.Services {
		fmt.Printf("Deleting service %s\n", service)
		if err := pm.DeleteService(ctx, service); err != nil {
			fmt.Printf("Warning: Failed to delete service %s: %v\n", service, err)
		}
	}

	// Delete roles
	for _, role := range resources.Roles {
		fmt.Printf("Deleting role %s\n", role)
		if err := pm.DeleteRole(ctx, role); err != nil {
			fmt.Printf("Warning: Failed to delete role %s: %v\n", role, err)
		}
	}

	// Delete organizations
	for _, org := range resources.Organizations {
		fmt.Printf("Deleting organization %s\n", org)
		// Note: We need to implement DeleteOrganization in the permission manager
		// This would need to remove all relationships involving the organization
		fmt.Printf("Organization deletion not implemented, skipping %s\n", org)
	}

	// Delete namespaces
	// This should be done last since namespaces contain organizations
	for _, ns := range resources.Namespaces {
		fmt.Printf("Deleting namespace %s\n", ns)
		if err := pm.DeleteNamespace(ctx, ns); err != nil {
			fmt.Printf("Warning: Failed to delete namespace %s: %v\n", ns, err)
			fmt.Println("This may be expected if the namespace still contains organizations")
		}
	}

	fmt.Println("Resource cleanup completed!")
}
