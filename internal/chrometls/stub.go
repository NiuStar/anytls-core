//go:build !with_utls

package chrometls

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/option"
)

// Factory is present even in builds that deliberately exclude uTLS.
type Factory struct{}

func (Factory) NewChromeClient(context.Context, string, option.OutboundTLSOptions) (tls.Config, error) {
	return nil, errors.New("uTLS is not included in this build; Chrome155 requires with_utls")
}
