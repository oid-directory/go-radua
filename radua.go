package radua

/*
radua.go contains top-level components which serve to implement an RADUA
under the terms of the draft-coretta-oiddir-radua I-D.
*/

import (
	"errors"

	"github.com/go-ldap/ldap/v3"
	"github.com/oid-directory/go-radir"
)

/*
DUA implements the Registration Authority Directory User Agent (RA DUA)
defined in, and described throughout, the [RADUA I-D].

[RADUA I-D]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-radua
*/
type DUA struct {
	dua ldap.Client
	cfg *radir.DUAConfig
	ech *Cache
}

/*
New returns an instance of *DUA alongside an error.

The input instance *[radir.DUAConfig] SHALL NOT be nil.

If no [ldap.Client] is provided, no LDAP DUA functionality will
be available.
*/
func New(cfg *radir.DUAConfig, dua ...ldap.Client) (radua *DUA, err error) {

	if cfg != nil {
		// add a dead cache just to avoid panics
		radua = &DUA{cfg: cfg, ech: invalidCache}
		if len(dua) > 0 {
			if dua[0] != nil {
				radua.dua = dua[0]
			}
		}
	} else {
		err = errors.New("One or more input instance are nil")
	}

	return
}

/*
SetCache assigns an instance of *[Cache] to the receiver instance.
*/
func (r *DUA) SetCache(cache *Cache) {
	if !r.IsZero() {
		if cache == nil {
			r.ech = invalidCache
		} else {
			r.ech = cache
		}
	}
}

/*
Cache returns the underlying instance of *[Cache] present within the
receiver instance, or a zero instance if unset.
*/
func (r *DUA) Cache() *Cache {
	var c *Cache = invalidCache
	if !r.IsZero() {
		if r.ech != invalidCache {
			c = r.ech
		}
	}
	return c
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *DUA) IsZero() bool {
	return r == nil
}

/*
Config returns the underlying instance of [*radir.DUAConfig] within the
receiver instance.
*/
func (r *DUA) Config() (cfg *radir.DUAConfig) {
	if !r.IsZero() {
		cfg = r.cfg
	}

	return
}

/*
Client returns the underlying instance of [ldap.Client] within the
receiver instance, or nil if unset.
*/
func (r *DUA) Client() (dua ldap.Client) {
	if !r.IsZero() {
		dua = r.dua
	}

	return
}

/*
Read is a convenience method which returns a Boolean instance alongside an
error following an attempt to read the entry described by e into dest,
which must be either an instance of *[radir.Registration] or *[radir.Registrant].

The Boolean value indicates whether the returned entry was derived from the
underlying [Cache] instance (true).

The context of e is determined by the dest type:

  - Where a *[radir.Registration] instance is passed as dest, e will be processed as a numeric OID ("[dotNotation]")
  - Where a *[radir.Registrant] instance is passed as dest, e will be processed as a "[registrantID]"
  - Where a *[radir.Subentry] instance is passed as dest, e will be processed as a distinguished name

Note that dest will be obliterated through re-initialization, thus user
driven initialization is unnecessary.

The purpose of this method is to automatically acquire and marshal the
intended [radir.Entry] instance from the upstream RA DSA. The search
scope for this operation is implicitly "[baseObject]", which is the
recommended default scope within the terms of the OID Directory I-D
series.

If the (optional) variadic useMap argument contains a value of true, any
instance of *[radir.Registration], *[radir.Registrant] or *[radir.Subentry]
(dest) shall be handled in [radir.Map] representation.  If a bonafide
[radir.Map] is passed as dest, it is handled as-is.

[baseObject]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.1
[registrantID]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-schema#section-2.3.34
[dotNotation]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-schema#section-2.3.2
*/
func (r *DUA) Read(e string, dest radir.Entry, useMap ...bool) (fromCache bool, err error) {
	if r.IsZero() {
		err = errors.New("Receiver instance is nil")
		return
	}

	switch tv := dest.(type) {
	case *radir.Registration:
		fromCache, err = r.readRegistration(e, tv)
	case *radir.Registrant:
		fromCache, err = r.readRegistrant(e, tv)
	case *radir.Subentry:
		fromCache, err = r.readSubentry(e, tv)
	case radir.Map:
		if oc, found := tv.StringsValue(`objectClass`); found {
			if strInSlice(`registration`, oc) {
				fromCache, err = r.readRegistration(e, tv)
			} else if strInSlice(`registrant`, oc) {
				fromCache, err = r.readRegistrant(e, tv)
			} else if strInSlice(`subentry`, oc) {
				fromCache, err = r.readSubentry(e, tv)
			} else {
				err = errors.New("Unsupported map type for read")
			}
		}
	default:
		err = errors.New("Unsupported destination type for read")
	}

	return
}

func (r *DUA) readRegistration(e string, dest radir.Entry) (
	fromCache bool,
	err error,
) {
	if dest == nil || e == "" {
		err = destNotInitErr
		return
	}

	pro := dest.Profile()

	funk := radir.DotNotToDN3D
	if pro.Model() == radir.TwoDimensional {
		funk = radir.DotNotToDN2D
	}

	switch tv := dest.(type) {
	case *radir.Registration:
		tv.SetDN(e, funk)
	case radir.Map:
		if tv[`dn`], err = funk(e,tv); err != nil {
			return
		}
	}
	srf := `(objectClass=registration)`

	fromCache, err = r.getOrRetrieve(dest.DN(), srf, dest)
	return
}

func (r *DUA) readRegistrant(e string, dest radir.Entry) (
	fromCache bool,
	err error,
) {
	if dest == nil || e == "" {
		err = destNotInitErr
		return
	}

	pro := dest.Profile()

	dn := `registrantID=` + e + `,` + pro.RegistrantBase()
	srf := `(objectClass=registrant)`

	switch tv := dest.(type) {
	case *radir.Registrant:
		tv.SetDN(e)
	case radir.Map:
		tv[`dn`] = e
	}

	fromCache, err = r.getOrRetrieve(dn, srf, dest)
	return
}

func (r *DUA) readSubentry(dn string, dest radir.Entry) (
	fromCache bool,
	err error,
) {

	if dest == nil || dn == "" {
		err = destNotInitErr
		return
	}

	srf := `(objectClass=subentry)`
	switch tv := dest.(type) {
	case *radir.Subentry:
		tv.SetDN(dn)
	case radir.Map:
		tv[`dn`] = dn
	}

	fromCache, err = r.getOrRetrieve(dn, srf, dest)
	return
}

func (r *DUA) getOrRetrieve(dn, srf string, dest radir.Entry) (fromCache bool, err error) {

	// Perform a pre-emptive read of the LDAP backend for the specified
	// DN (and *ONLY* with a request of the DN attribute and NO others).
	// If the return code is anything other than zero (0), a.k.a. success,
	// the request is denied. This helps to prevent unauthorized disclosure
	// of sensitive (whole) entries.
	asr := ldap.NewSearchRequest(dn, 0, 0, 0, 0, false, srf, []string{"dn"}, nil)
	if _, err = r.dua.Search(asr); err != nil && !ldap.IsErrorWithCode(err, uint16(0)) {
		return
	}

	if !r.ech.IsZero() {
		switch kind := r.ech.Kind(dn); kind {
		case "registration":
			dest = r.ech.Registration(dn)
		case "registrant":
			dest = r.ech.Registrant(dn)
		case "subentry":
			dest = r.ech.Subentry(dn)
		}
		fromCache = dest != nil
	}

	if !fromCache {
		selector := radir.AttributeSelector{}
		sra := selector.All()

		// Entry was not cached, or cache is disabled.
		sr := ldap.NewSearchRequest(dn, 0, 0, 0, 0, false, srf, sra, nil)

		var res *ldap.SearchResult
		if res, err = r.dua.Search(sr); err == nil {
			if ct := len(res.Entries); ct != 1 {
				err = throwEntryCountErr(ct, 1)
				return
			}

			if err = res.Entries[0].UnmarshalFunc(dest, unmarshalFunc); err == nil {
				r.ech.Add(dest, radir.TTLPrecedenceFromEntry(dest))
			}
		}
	}

	return
}

var (
	destNotInitErr error = errors.New("Destination instance not initialized")
	entryCountErr  error = errors.New("Invalid entry count")
)

func throwEntryCountErr(got, want int) error {
	return errors.New(entryCountErr.Error() + `; want ` + itoa(want) + `, got ` + itoa(got))
}
