package idempotency

import (
	"context"

	"github.com/mori-box/moribox-shared/ids"
)

// resourceHolder lets a handler publish the identifier of the resource it
// created so that the stored idempotency record points at it.
type resourceHolder struct{ id ids.Opt }

const resourceContextKey contextKey = 100

func contextWithValues(ctx context.Context, key, scope, hash string) context.Context {
	ctx = context.WithValue(ctx, keyContextKey, key)
	ctx = context.WithValue(ctx, scopeContextKey, scope)
	ctx = context.WithValue(ctx, hashContextKey, hash)
	return context.WithValue(ctx, resourceContextKey, &resourceHolder{})
}

// SetResourceID records the created resource for the idempotency record.
func SetResourceID(ctx context.Context, id ids.ID) {
	if holder, ok := ctx.Value(resourceContextKey).(*resourceHolder); ok {
		holder.id = ids.Some(id)
	}
}

func resourceIDFromContext(ctx context.Context) ids.Opt {
	if holder, ok := ctx.Value(resourceContextKey).(*resourceHolder); ok {
		return holder.id
	}
	return ids.None()
}
