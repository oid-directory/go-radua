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
		radua = &DUA{cfg: cfg, ech: invalidCache}
		if len(dua) > 0 {
			if dua[0] != nil {
				radua.dua = dua[0]
			}
		}
	} else {
		err = errors.New("One or more input instance are nil")
	}

	// add a dead cache just to avoid panics
	radua.ech = invalidCache

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
Read is a convenience method which returns an instance of error following
an attempt to read the entry described by e into dest, which must be either
an instance of *[radir.Registration] or *[radir.Registrant].

The context of e is determined by the dest type:

  - Where a *[radir.Registration] instance is passed as dest, e will be processed as a numeric OID ("[dotNotation]")
  - Where a *[radir.Registrant] instance is passed as dest, e will be processed as a "[registrantID]"
  - Where a *[radir.Subentry] instance is passed as dest, e will be processed as a distinguished name

Note that dest will be obliterated through re-initialization, thus user
driven initialization is unnecessary.

The purpose of this method is to automatically acquire and marshal the
intended *[ldap.Entry] instance from the upstream RA DSA into an instance
of *[radir.Registration]. The search scope for this operation is implicitly
"[baseObject]", which is the recommended default scope within the terms of
the OID Directory I-D series.

[baseObject]: https://datatracker.ietf.org/doc/html/rfc4511#section-4.5.1.1
[registrantID]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-schema#section-2.3.34
[dotNotation]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-schema#section-2.3.2
*/
func (r *DUA) Read(e string, dest any) (err error) {
	if r.IsZero() {
		err = errors.New("Receiver instance is nil")
		return
	}

	pro := r.cfg.Profile()

	switch tv := dest.(type) {
	case *radir.Registration:
		err = r.readRegistration(e, pro, tv)
	case *radir.Registrant:
		err = r.readRegistrant(e, pro, tv)
	case *radir.Subentry:
		//err = r.readSubentry(e, pro, tv)
		//case *radir.Subentry:
		//	tv = pro.NewSubentry()
		//	dn = e
		//	dest = tv
	default:
		err = errors.New("Unsupported destination type for read")
	}

	return
}

func (r *DUA) readRegistration(e string, pro *radir.DITProfile, dest *radir.Registration) (err error) {
	if dest.IsZero() {
		err = destNotInitErr
		return
	}

	dest.R_DITProfile = pro

	funk := radir.DotNotToDN3D
	if pro.Model() == radir.TwoDimensional {
		funk = radir.DotNotToDN2D
	}

	dest.SetDN(e, funk)
	srf := `(objectClass=registration)`

	err = r.getOrRetrieve(dest.DN(), srf, dest)
	return
}

func (r *DUA) readRegistrant(e string, pro *radir.DITProfile, dest *radir.Registrant) (err error) {
	if dest.IsZero() {
		err = destNotInitErr
		return
	}

	dest.R_DITProfile = pro

	dn := `registrantID=` + e + `,` + pro.RegistrantBase()
	srf := `(objectClass=registrant)`
	dest.SetDN(e)

	err = r.getOrRetrieve(dn, srf, dest)
	return
}

func (r *DUA) readSubentry(cn, parent string, pro *radir.DITProfile, dest *radir.Subentry) (err error) {
	if dest.IsZero() || cn == "" || parent == "" {
		err = destNotInitErr
		return
	}

	dn := `cn=` + cn + `,` + parent
	srf := `(objectClass=subentry)`
	dest.SetDN(dn)

	err = r.getOrRetrieve(dn, srf, dest.Marshal)
	return
}

func (r *DUA) getOrRetrieve(dn, srf string, dest any) (err error) {

	selector := radir.AttributeSelector{}
	sra := selector.All()

	var fromCache bool
	if !r.ech.IsZero() {
		switch kind := r.ech.Kind(dn); kind {
		case "registration":
			if _, fromCache = dest.(*radir.Registration); fromCache {
				(*dest.(*radir.Registration)) = (*r.ech.Registration(dn))
			}
		case "registrant":
			if _, fromCache = dest.(*radir.Registrant); fromCache {
				(*dest.(*radir.Registrant)) = (*r.ech.Registrant(dn))
			}
		}
	}

	if !fromCache {
		// Entry was not cached, or cache is disabled.
		sr := ldap.NewSearchRequest(dn, 0, 0, 0, 0, false, srf, sra, nil)

		var res *ldap.SearchResult
		if res, err = r.dua.Search(sr); err == nil {
			if ct := len(res.Entries); ct != 1 {
				err = throwEntryCountErr(ct, 1)
				return
			}

			if err = res.Entries[0].UnmarshalFunc(dest, unmarshalFunc); err == nil {
				r.ech.Add(dest, 15) // ignored if cache is disabled.
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
