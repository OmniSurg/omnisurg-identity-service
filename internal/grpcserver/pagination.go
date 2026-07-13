package grpcserver

import (
	"strconv"

	commonv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/common/v1"
)

// pageToLimitOffset maps the proto cursor Page onto the limit and offset the
// service layer expects. The cursor is an opaque numeric offset string in P1
// (the service is offset based); a malformed cursor falls back to offset 0. A
// zero limit lets the service apply its own default. This keeps the wire
// contract cursor based while the service stays offset based behind it.
func pageToLimitOffset(p *commonv1.Page) (limit, offset int32) {
	if p == nil {
		return 0, 0
	}
	limit = p.GetLimit()
	if c := p.GetCursor(); c != "" {
		if parsed, err := strconv.ParseInt(c, 10, 32); err == nil && parsed >= 0 {
			offset = int32(parsed)
		}
	}
	return limit, offset
}

// pageInfo builds the response PageInfo from the total count. The next cursor is
// left empty in P1; the BFF pages by passing an explicit offset cursor.
func pageInfo(total int64) *commonv1.PageInfo {
	return &commonv1.PageInfo{TotalCount: total}
}
