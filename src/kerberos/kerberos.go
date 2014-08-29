package kerberos

// #cgo LDFLAGS: -lkrb5 -lk5crypto -lcom_err
// #include <krb5.h>
import "C"

type Context struct {
	ctx C.krb5_context
}

const (
	maxLnameSz = 255
)

func NewContext(secure bool) (*Context, error) {
	var ctx C.krb5_context
	var code C.krb5_error_code
	if secure {
		code = C.krb5_init_secure_context(&ctx)
	} else {
		code = C.krb5_init_context(&ctx)
	}
	if code != 0 {
		return nil, Error{
			Code: int(code),
			Msg:  "Cannot initialize Kerberos Context"}
	}
	return &Context{ctx: ctx}, nil
}

func (c *Context) Free() {
	if c.ctx != nil {
		C.krb5_free_context(c.ctx)
		c.ctx = nil
	}
}

func (c *Context) newError(code C.krb5_error_code) error {
	msg := C.krb5_get_error_message(c.ctx, code)
	C.krb5_clear_error_message(c.ctx)
	defer C.krb5_free_error_message(c.ctx, msg)
	return Error{Code: int(code), Msg: C.GoString(msg)}
}

func (c *Context) NewPrincipal(pname string) (*Principal, error) {
	var princ C.krb5_principal
	pnameC := C.CString(pname)
	defer C.krb5_free_string(c.ctx, pnameC)
	code := C.krb5_parse_name(c.ctx, pnameC, &princ)
	if code != 0 {
		return nil, c.newError(code)
	}
	return &Principal{princ: princ}, nil
}

func (c *Context) FreePrincipal(p *Principal) {
	if p.princ != nil {
		C.krb5_free_principal(c.ctx, p.princ)
		p.princ = nil
	}
}

func (c *Context) Localname(p *Principal) (string, error) {
	buf := new([maxLnameSz]C.char)
	code := C.krb5_aname_to_localname(c.ctx, p.princ, maxLnameSz, &buf[0])
	if code != 0 {
		return "", c.newError(code)
	}
	return C.GoStringN(&buf[0], maxLnameSz), nil
}

func (c *Context) Unparse(p *Principal) (string, error) {
	var buf *C.char
	defer C.krb5_free_unparsed_name(c.ctx, buf)
	code := C.krb5_unparse_name(c.ctx, p.princ, &buf)
	if code != 0 {
		return "", c.newError(code)
	}
	return C.GoString(buf), nil
}

type Error struct {
	Code int
	Msg  string
}

func (e Error) Error() string {
	return e.Msg
}

type Principal struct {
	princ C.krb5_principal
}
