
> Is this user allowed to perform this action on this resource?

For example:

- Can Abebe transfer money from his linked bank account?
- Can a customer access another customer's account?
- Can a bank administrator view a transfer?
- Can a customer use Telebirr?

Casbin lets you define these rules separately from your business logic.

# 1. Authentication vs. authorization

First, understand the difference.

Authentication

## Who are you?

A customer logs in with a username and password. Your application verifies their credentials and identifies them as `customer-001`.

Authorization

## What are you allowed to do?

Casbin checks whether `customer-001` can transfer money using a particular account.

Casbin handles authorization, not login or password verification. Your Go application is responsible for authenticating the customer and passing their trusted identity to Casbin.

# 2. The three main concepts in Casbin

Casbin uses three main elements to evaluate a request.

| Element         | Meaning                     | Your banking example |
| --------------- | --------------------------- | -------------------- |
| Subject (`sub`) | Who is making the request?  | Retail customer      |
| Object (`obj`)  | What are they accessing?    | Linked bank account  |
| Action (`act`)  | What are they trying to do? | Transfer             |

For example, this is a request:

```
enforcer.Enforce(
    customer,
    account,
    "transfer",
)
```

It asks Casbin:

"Is this customer allowed to transfer money using this account?"

The `Enforce()` function evaluates the request and returns either `true` or `false`, along with an error if evaluation fails.

# 3. Understanding your Casbin model

Your model is the configuration that tells Casbin how to make authorization decisions.

Let's look at each section.

## A. Request definition

```
[request_definition]
r = sub, obj, act
```

This defines what information Casbin receives when you call `Enforce()`.

- `sub`: the customer or user
- `obj`: the resource, such as an account and service
- `act`: the action, such as `transfer` or `view`

In your Go code:

```
enforcer.Enforce(customer, resource, "transfer")
```

The three arguments correspond to `sub`, `obj`, and `act`, respectively.

## B. Policy definition

```
[policy_definition]
p = sub, obj, act
```

A policy is a rule describing what a role is allowed to do.

For example:

```
enforcer.AddPolicy(
    "customer",
    "BANK_TRANSFER",
    "transfer",
)
```

This means the `customer` role is allowed to perform the `transfer` action on the `BANK_TRANSFER` service.

Notice that the policy doesn't specify a particular customer. It defines permissions for a role.

## C. Role definition

```
[role_definition]
g = _, _
```

This tells Casbin that you want to use role relationships.

For example:

```
enforcer.AddGroupingPolicy(
    "retail_customer",
    "customer",
)
```

This means `retail_customer` inherits the permissions of `customer`.

retail_customer

Assigned to Abebe

inherits permissions

customer

Role with permissions

BANK_TRANSFER

transfer

This is called role inheritance. You can assign permissions to a general role and let other roles inherit them.

## D. Policy effect

```
[policy_effect]
e = some(where (p.eft == allow))
```

This tells Casbin how to combine matching policies.

Here, `some` means that if at least one policy allows the request, the policy effect is an allow.

If no policy matches, the request is denied.

## E. Matcher

```
[matchers]
m = g(r.sub.Role, p.sub) &&
    r.obj.Service.Code == p.obj &&
    r.act == p.act &&
    r.obj.Account.Active == true &&
    (r.sub.Role == "bank_admin" ||
     r.obj.Account.UserID == r.sub.ID)
```

The matcher is the heart of your authorization logic. It checks whether the request satisfies the policy and the additional attribute conditions.

Let's examine each condition.

| Expression                         | What it checks                                  |
| ---------------------------------- | ----------------------------------------------- |
| `g(r.sub.Role, p.sub)`             | Does the user's role inherit the policy's role? |
| `r.obj.Service.Code == p.obj`      | Does the requested service match the policy?    |
| `r.act == p.act`                   | Does the requested action match the policy?     |
| `r.obj.Account.Active == true`     | Is the linked account active?                   |
| `r.sub.Role == "bank_admin"`       | Is the user a bank admin?                       |
| `r.obj.Account.UserID == r.sub.ID` | Does the account belong to the user?            |

The `&&` operator means AND: every condition must be true.

The `||` operator means OR: either condition can be true.

The parentheses ensure that the final ownership check can be bypassed by a bank admin, but the account must still be active.

# 4. Understanding RBAC and ABAC in your POC

Your example combines two authorization approaches.

RBAC

# Role-Based Access Control

RBAC answers: What can this role do?

For example, your policies say:

```
{"customer", "BANK_TRANSFER", "transfer"}
{"customer", "TELEBIRR", "transfer"}
{"admin", "BANK_TRANSFER", "view"}
```

This means customers can transfer through the two services, while admins can view bank transfers.

ABAC

# Attribute-Based Access Control

ABAC answers: Does the request satisfy the required conditions?

For example:

```
r.obj.Account.Active == true
```

This checks whether the account is active.

```
r.obj.Account.UserID == r.sub.ID
```

This checks whether the account belongs to the requesting customer.

The benefit of combining them is that a customer can have permission to transfer money, but still be denied if they try to use someone else's account.

# 5. Let's follow a real request

Suppose Abebe has this customer record:

```
customer := RetailCustomer{
    ID:       "customer-001",
    Username: "abebe",
    Role:     "retail_customer",
}
```

And this linked account:

```
account := LinkedAccount{
    ID:        "linked-001",
    UserID:    "customer-001",
    AccountNo: "1000123456789",
    Active:    true,
}
```

He tries to transfer money using the bank transfer service:

```
allowed, err := enforcer.Enforce(
    customer,
    Resource{
        Account: account,
        Service: bankTransfer,
    },
    "transfer",
)
```

Here's what happens internally.

## Authorization evaluation

Abebe → bank transfer → transfer

1\. Role check

`retail_customer` inherits `customer`.

Pass

2\. Service check

`BANK_TRANSFER` matches the policy.

Pass

3\. Action check

`transfer` matches the policy.

Pass

4\. Account status check

The account is active.

Pass

5\. Ownership check

Both user IDs are `customer-001`.

Pass

# Allowed

Enforce returns true

Now imagine Abebe tries to use another customer's account:

```
otherAccount := LinkedAccount{
    ID:        "linked-002",
    UserID:    "customer-002",
    AccountNo: "1000987654321",
    Active:    true,
}
```

The role, service, action, and account status checks all pass. However, the ownership check fails.

Since Abebe isn't an admin, the final condition is false. Casbin denies the request.

# 6. How Casbin fits into your Go application

In a real banking application, the authorization process might look like this:

Customer

Logs in and requests a transfer

Authentication middleware

Verifies JWT and extracts user ID

Load account and service

Fetch trusted attributes from your database

Casbin Enforce()

Evaluates role, service, action, and attributes

Allowed

Continue to transfer

Denied

Return HTTP 403

For your POC, you created the users, accounts, and policies directly in `main.go`. In production, you would load the user and account attributes from your database and manage policies separately.

One important security detail: never trust the account owner ID or role sent by the client. Get those from your authenticated identity and trusted database records.

# 7. What you should remember

| Concept          | In your POC                              |
| ---------------- | ---------------------------------------- |
| Model            | Defines how authorization works          |
| Request          | Customer, resource, and action           |
| Policy           | Defines role permissions                 |
| Role inheritance | Connects `retail_customer` to `customer` |
| Matcher          | Combines role and attribute checks       |
| Enforce          | Evaluates the request                    |
| Allow            | Returns `true`                           |
| Deny             | Returns `false`                          |

The most important idea: Casbin doesn't know your banking rules automatically. You teach it those rules through the model, policies, and attributes you provide.

