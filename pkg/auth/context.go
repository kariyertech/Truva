package auth

import (
	"context"
)

// Context keys for user information
type contextKey string

const (
	userIDKey      contextKey = "user_id"
	usernameKey    contextKey = "username"
	userRolesKey   contextKey = "user_roles"
	UserContextKey contextKey = "user_context"
)

// SetUserContext adds user information to the context
func SetUserContext(ctx context.Context, userID, username string, roles []string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, usernameKey, username)
	ctx = context.WithValue(ctx, userRolesKey, roles)
	return ctx
}

// GetUserID retrieves user ID from context
func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(userIDKey).(string); ok {
		return userID
	}
	return ""
}

// GetUsername retrieves username from context
func GetUsername(ctx context.Context) string {
	if username, ok := ctx.Value(usernameKey).(string); ok {
		return username
	}
	return ""
}

// GetUserRoles retrieves user roles from context
func GetUserRoles(ctx context.Context) []string {
	if roles, ok := ctx.Value(userRolesKey).([]string); ok {
		return roles
	}
	return []string{}
}

// IsAuthenticated checks if user is authenticated
func IsAuthenticated(ctx context.Context) bool {
	return GetUserID(ctx) != ""
}

// HasRole checks if user has a specific role
func HasRole(ctx context.Context, role string) bool {
	userRoles := GetUserRoles(ctx)
	for _, userRole := range userRoles {
		if userRole == role {
			return true
		}
	}
	return false
}

// HasAnyRole checks if user has any of the specified roles
func HasAnyRole(ctx context.Context, roles ...string) bool {
	userRoles := GetUserRoles(ctx)
	for _, userRole := range userRoles {
		for _, role := range roles {
			if userRole == role {
				return true
			}
		}
	}
	return false
}
