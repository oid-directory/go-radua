package radua

import (
	"reflect"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/oid-directory/go-radir"
)

var (
	cntns  func(string, string) bool     = strings.Contains
	atoi   func(string) (int, error)     = strconv.Atoi
	itoa   func(int) string              = strconv.Itoa
	lc     func(string) string           = strings.ToLower
	split  func(string, string) []string = strings.Split
	streqf func(string, string) bool     = strings.EqualFold
	hasPfx func(string, string) bool     = strings.HasPrefix
)

func deriveTTL(ent record, minutes ...any) (m int) {
       if len(minutes) > 0 {
		m = assertTTL(minutes[0])
       } else {
		m = assertTTL(selectTTL(ent.Profile().TTL(),
			ent.TTL(), ent.CTTL()))
       }

	// Package default TTL (DefaultRATTL var;
	// only used if all of the above were
	// effectively zero (0))
       if m <= 0 {
               m = DefaultRATTL
       }

       return
}

func selectTTL(pttl, ettl, cttl string) (ttl string) {
	// TTL Precedence:
	//  - 1. Profile TTL
	//  - 2. COLLECTIVE entry TTL (overrides #1)
	//  - 3. Explicit entry TTL (overrides #2)
	if len(pttl) > 0 {
		ttl = pttl
	}

	if len(cttl) > 0 {
		ttl = cttl
	}

	if len(ettl) > 0 {
		ttl = ettl
	}

	return
}

func assertTTL(ttl any) (t int) {
	switch tv := ttl.(type) {
	case string:
		t, _ = atoi(tv)
	case int:
		t = tv
	}

	return
}

func splitTags(tagData string) (tags []string) {
	push := func(val ...string) {
		for i := 0; i < len(val); i++ {
			if !strInSlice(val[i], tags) {
				tags = append(tags, val[i])
			}
		}
	}

	_tags := strings.Split(tagData, `|`)
	for i := 0; i < len(_tags); i++ {
		if tag := _tags[i]; cntns(tag, `;`) {
			t := split(tag, `;`)
			push(t[0])
			for j := 1; j < len(t); j++ {
				push(t[0] + `;` + t[j])
			}
		} else if hasPfx(tag, `c-`) {
			push(tag, tag+`;collective`)
		} else {
			push(tag)
		}
	}

	return
}

/*
unmarshalFunc returns an error following an attempt to unmarshal an *ldap.Entry
attribute value into the appropriate struct field of a destination type instance
(either *radir.Registration or *radir.Registrant).

This function is meant to be passed via closure to [ldap.Entry.UnmarshalFunc].
*/
func unmarshalFunc(entry *ldap.Entry, fieldType reflect.StructField, fieldValue reflect.Value) (err error) {
	if tagData, ok := fieldType.Tag.Lookup("ldap"); ok {
		tags := splitTags(tagData)
		var found bool

		for _, tag := range tags {
			if found || tag == "-" {
				// Our tags are an "OR" statement, so if
				// we matched a previous iteration, we'll
				// exit now. Also use this opportunity to
				// break out of any iteration with a "-"
				// as the tag.
				break
			} else if tag == "dn" {
				// DN is not an attribute value per se, thus
				// we have to set it manually.
				fieldValue.SetString(entry.DN)
				break
			}

			// always assume multi-value to begin with ...
			value := entry.GetAttributeValues(tag)

			switch fieldValue.Interface().(type) {
			case string:
				if fieldValue.IsZero() && len(value) > 0 {
					// Only set if field was empty ...
					fieldValue.SetString(value[0])
					found = true
				}
			case []string:
				if fieldValue.IsZero() {
					fieldValue.Set(reflect.ValueOf(value)) // init+clobber
				} else {
					for i := 0; i < len(value); i++ {
						if !strInSlice(value[i], fieldValue.Interface().([]string)) {
							reflect.Append(fieldValue, reflect.ValueOf(value[i])) // append
						}
					}
				}
				found = true
			}
		}
	} else {
		// there was no tag. This will result in a descension
		// into a struct (or ptr to struct)
		err = descendUnmarshalFunc(entry, fieldValue)
	}

	return
}

func descendUnmarshalFunc(entry *ldap.Entry, fieldValue reflect.Value) (err error) {
	var dest reflect.Value = fieldValue
	if fieldValue.IsZero() {
		// Initialize the destination type instance
		// prior to descending into it ...
		dest = reflect.New(fieldValue.Type().Elem())
	}

	// Matches result in recursive closure
	// calls of this function.
	switch tv := dest.Interface().(type) {
	case *radir.X660, *radir.X667, *radir.X680, *radir.X690,
		*radir.Spatial, *radir.Supplement, *radir.CurrentAuthority,
		*radir.FirstAuthority, *radir.Sponsor:
		if err = entry.UnmarshalFunc(tv, unmarshalFunc); err == nil {
			fieldValue.Set(reflect.ValueOf(tv))
		}
	}

	return
}

/*
strInSlice returns a Boolean value indicative of the presence of
r within the input slice value.  The optional variadic input value
cEM indicates whether the matching process should recognize exact
case folding. r may be string or []string.

By default, case is not significant in the matching process unless
a value of true is supplied as cEM (caseExactMatch).
*/
func strInSlice(r any, slice []string, cEM ...bool) (match bool) {
	// assume caseIgnoreMatch by default
	funk := streqf
	if len(cEM) > 0 {
		if cEM[0] {
			// use caseExactMatch behavior
			funk = func(a, b string) bool {
				return a == b
			}
		}
	}

	switch tv := r.(type) {
	case string:
		for i := 0; i < len(slice) && !match; i++ {
			match = funk(tv, slice[i])
		}
	case []string:
		for i := 0; i < len(tv) && !match; i++ {
			for j := 0; j < len(slice) && !match; j++ {
				match = funk(tv[i], slice[j])
			}
		}
	}

	return
}

/*
TTL returns the effective time-to-live for the receiver instance, taking
into account *[DITProfile]-inherited values as well as subtree-based
(COLLECTIVE) and entry literal values. The output can be used to instruct
instances of [Cache] when, and when not, to cache an instance.

See [Section 2.2.3.4 of the RADUA I-D] for details related to TTL precedence
when handling multiple TTL directives.

[Section 2.2.3.4 of the RADUA I-D]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-radua#section-2.2.3.4
*/
//func (r *Registrant) TTL() string {
//        ct := r.DITProfile().TTL()
//        lt := selectTTL(r.R_TTL, r.R_TTL)
//
//        if lt == `` {
//                return ct
//        }
//
//        return lt
//}
