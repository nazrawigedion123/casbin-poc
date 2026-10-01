package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

// Retail customer
type RetailCustomer struct {
	ID       string
	Name     string
	Username string
	Role     string
}

// Linked bank account
type LinkedAccount struct {
	ID        string
	UserID    string
	AccountNo string
	Active    bool
}

// Banking service
type Service struct {
	ID   string
	Name string
	Code string
}

// Request object combines account and service attributes.
type Resource struct {
	Account LinkedAccount
	Service Service
}

func main() {
	// 1. Define the Casbin model.
	modelText := `
	[request_definition]
	r = sub, obj, act

	[policy_definition]
	p = sub, obj, act

	[role_definition]
	g = _, _

	[policy_effect]
	e = some(where (p.eft == allow))

	[matchers]
	m = g(r.sub.Role, p.sub) && r.obj.Service.Code == p.obj && r.act == p.act && r.obj.Account.Active == true && (r.sub.Role == "bank_admin" || r.obj.Account.UserID == r.sub.ID)
`
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		log.Fatal(err)
	}

	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Define roles.
	// A retail customer inherits customer permissions.
	// An admin inherits admin permissions.
	_, err = enforcer.AddGroupingPolicy(
		"retail_customer", "customer",
	)
	if err != nil {
		log.Fatal(err)
	}

	_, err = enforcer.AddGroupingPolicy(
		"bank_admin", "admin",
	)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Define role permissions.
	// p = role, service_code, action

	policies := [][]string{
		{"customer", "BANK_TRANSFER", "transfer"},
		{"customer", "TELEBIRR", "transfer"},
		{"admin", "BANK_TRANSFER", "transfer"},
		{"admin", "TELEBIRR", "transfer"},
		{"admin", "BANK_TRANSFER", "view"},
		{"admin", "TELEBIRR", "view"},
	}

	for _, p := range policies {
		_, err := enforcer.AddPolicy(p)
		if err != nil {
			log.Fatal(err)
		}
	}

	// 4. Sample customers.
	customer := RetailCustomer{
		ID:       "customer-001",
		Name:     "Abebe Kebede",
		Username: "abebe",
		Role:     "retail_customer",
	}

	admin := RetailCustomer{
		ID:       "admin-001",
		Name:     "Bank Admin",
		Username: "admin",
		Role:     "bank_admin",
	}

	// 5. Sample linked accounts.
	account := LinkedAccount{
		ID:        "linked-001",
		UserID:    "customer-001",
		AccountNo: "1000123456789",
		Active:    true,
	}

	otherAccount := LinkedAccount{
		ID:        "linked-002",
		UserID:    "customer-002",
		AccountNo: "1000987654321",
		Active:    true,
	}

	inactiveAccount := LinkedAccount{
		ID:        "linked-003",
		UserID:    "customer-001",
		AccountNo: "1000111111111",
		Active:    false,
	}

	// 6. Define services.
	bankTransfer := Service{
		ID:   "service-001",
		Name: "bank_transfer",
		Code: "BANK_TRANSFER",
	}

	telebirr := Service{
		ID:   "service-002",
		Name: "telebirr",
		Code: "TELEBIRR",
	}

	// 7. Test authorization.
	check := func(
		user RetailCustomer,
		account LinkedAccount,
		service Service,
		action string,
	) {
		resource := Resource{
			Account: account,
			Service: service,
		}

		allowed, err := enforcer.Enforce(
			user, resource, action,
		)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf(
			"User: %-10s | Account: %-10s | Service: %-15s | Action: %-8s | Allowed: %v\n",
			user.Username,
			account.ID,
			service.Name,
			action,
			allowed,
		)
	}

	// Customer accessing their own account.
	check(customer, account, bankTransfer, "transfer")
	check(customer, account, telebirr, "transfer")

	// Customer trying to access another customer's account.
	check(customer, otherAccount, bankTransfer, "transfer")

	// Customer trying to access an inactive account.
	check(customer, inactiveAccount, bankTransfer, "transfer")

	// Customer trying an unauthorized action.
	check(customer, account, bankTransfer, "view")

	// Admin accessing another customer's account.
	check(admin, otherAccount, bankTransfer, "transfer")

	// Admin accessing an inactive account.
	check(admin, inactiveAccount, bankTransfer, "transfer")
}
