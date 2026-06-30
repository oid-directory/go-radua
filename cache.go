package radua

/*
cache.go offers a generic, thread-safe, in-memory
caching subsystem for radir.Entry interface values.
*/

import (
	"encoding/gob"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/oid-directory/go-radir"
)

/*
DefaultRATTL serves as a fallback TTL value to be used
to direct the *[Cache] instance as to how long a given
[radir.Entry] instance should be cached. This value is
only taken into account if all other TTL sources are
effectively zero (0).
*/
var DefaultRATTL = 1440 // one (1) day

/*
cachedEntry contains any [radir.Entry] instance alongside an expiry [time.Time] instance.

Instances of this type are stored within an instance of *[Cache] and need not
be managed directly by the user.
*/
type cachedEntry struct {
	Value  radir.Entry
	Expiry time.Time
}

var invalidCache *Cache = &Cache{}

/*
Expired returns a Boolean value indicative of whether the receiver instance
has expired. A value of true is returned if the instance cannot be found.

Note that, unlike [Cache.Entry], use of this method will not result in the
deletion of an expired instance.
*/
func (r *Cache) Expired(dn string) bool {
	var exp bool
	if !r.IsZero() && len(dn) > 0 {
		r.lock.Lock()
		defer r.lock.Unlock()

		exp = true // coverage
		if item, _ := r.entries[lc(dn)]; item.Value != nil {
			exp = time.Now().After(item.Expiry)
		}
	}

	return exp
}

/*
TTL returns the remaining time-to-live (in minutes) for the specified
entry.

A return of -1 indicates an error (e.g.: zero input or a disabled cache).

A return value of 0 means the entry has already expired or does not exist.

Any other positive return value indicates the number of minutes remaining
until expiry.
*/
func (r *Cache) TTL(dn string) int {
	var ttl int = -1
	if !r.IsZero() && len(dn) > 0 {
		r.lock.Lock()
		defer r.lock.Unlock()

		ttl = 0
		if item, _ := r.entries[lc(dn)]; item.Value != nil {
			ttl = int(item.Expiry.Sub(time.Now()).Minutes())
			if ttl <= 0 {
				ttl = 0
			}
		}
	}
	return ttl
}

/*
Cache is a thread-safe, memory-based caching type, meant to store any
number of [radir.Entry] instances for the purpose of reducing LDAP
network utilization. Caching is covered in the [RADUA] and [RASCHEMA] IDs.

Instances of either type are associated with their respective LDAP DNs,
which are queried immediately prior to an LDAP Search.

Unexpired instances found within a *[Cache] that match the queried DN are
returned instead of reaching out to the RA DSA.

Requesting cached instances that have since expired will result in their
immediate annihilation and a nil return. Under ordinary circumstances,
at this point the DUA could reach out to the directory in an attempt to
re-acquire the now-expired instance.

The [NewCache] function initializes and returns instances of this type.

Following initialization, an instance of *[Cache] may be written to file
using the [Cache.Write].

Conversely, the [Cache.Load] method allows an unfrozen *[Cache] to be
loaded from file.

The [Cache.Entry] method allows accessing unexpired cached instances.
Attempting to access a cached instance that has since expired will
result in its deletion unless the *[Cache] has been frozen.

The [Cache.Len] method returns the current respective integer length of
a *[Cache]. The [Cache.Cap] method returns the maximum number of elements
permitted within a *[Cache].

The [Cache.Expired] method safely allows expiration checks of specific
cached instances without the risk of deletion. The [Cache.Keys] returns
string slices of cached element DNs, also without deletion risk.

The [Cache.Add] method allows the addition of elements into the *[Cache],
provided it is not frozen.

The [Cache.Remove] method allows for the removal of select instances from
an unfrozen *[Cache], regardless of the expiration status.

The [Cache.Touch] method allows for expired -- but as-of-yet undeleted --
cached instances to be "reborn" or "resurrected" if the *[Cache] is not
frozen.  A "touch" effectively results in the reset of the respective
"expiration timer" to the specified duration.

The [Cache.Freeze] and [Cache.Thaw] methods impose read-only and read-write
policies respectively, influencing the ability for updates and amendments
to the *[Cache] to be recognized. The [Cache.Frozen] method offers a means
for checking the frozen state of a *[Cache]. A frozen *[Cache] will always
permit read operations. When first initialized, a *[Cache] is always in a
thawed state.

[Cache.Tidy] and [Cache.Flush] can be used to clean-up or outright purge
multiple instances from an unfrozen *[Cache]. The [Cache.IsZero] method
reveals whether the instance has been initialized or not. [Cache.Free]
destroys the *[Cache] -- regardless of freeze state.

[RADUA]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-radua
[RASCHEMA]: https://datatracker.ietf.org/doc/html/draft-coretta-oiddir-schema
*/
type Cache struct {
	threshold int
	lock      *sync.Mutex
	frozen    bool
	entries   map[string]cachedEntry
}

/*
NewCache returns a freshly initialized instance of *[Cache].

The registrationMax and registrantMax integer input values define the
maximum number of entries that will be cached respectively. Specifying
0 disables the respective threshold.

Attempts to exceed this threshold will silently disregard submissions
for NEW (uncached) instances, however previously cached instances will
still be refreshed.
*/
func NewCache(m ...int) *Cache {
	var maximum int
	if len(m) > 0 {
		if m[0] >= 0 {
			maximum = m[0]
		}
	}

	return &Cache{
		threshold: maximum,
		lock:      &sync.Mutex{},
		entries:   make(map[string]cachedEntry, maximum),
	}
}

/*
IsZero returns a Boolean value indicative of a nil receiver state.
*/
func (r *Cache) IsZero() bool {
	return r == nil || r == invalidCache
}

/*
Len returns the integer length of the receiver instance, thereby revealing
how many [radir.Entry] instances are cached.

This method does not take expiration into account, nor does its use trigger any
expiration purges.
*/
func (r *Cache) Len() (l int) {
	if !r.IsZero() {
		l = len(r.entries)
	}

	return
}

/*
Cap returns the maximum permitted number of [radir.Entry] instances that
may be cached.

A value of zero (0) indicates no limits are imposed upon caching requests
of this form.
*/
func (r *Cache) Cap() (c int) {
	if !r.IsZero() {
		c = len(r.entries)
	}

	return
}

/*
Registration returns an instance of [radir.Entry] following a search for the
input dn value within the receiver instance.

A nil return value can indicate any of the following:

  - Instance had expired and has since been purged, or has not yet been cached
  - Instance was found but was nil, indicating caching is disabled for the entry
  - Instance was neither a *[radir.Registration] nor a [radir.Map]

Case is not significant in the distinguished name matching process.
*/
func (r *Cache) Registration(dn string) (entry radir.Entry) {
	switch tv := r.call(dn, "registration").(type) {
	case *radir.Registration:
		entry = tv
	case radir.Map:
		entry = tv
	}
	return entry
}

/*
Registrant returns an instance of [radir.Entry] following a search
for the input dn value within the receiver instance.

A nil return value can indicate any of the following:

  - Instance had expired and has since been purged, or has not yet been cached
  - Instance was found but was nil, indicating caching is disabled for the entry
  - Instance was neither a *[radir.Registrant] nor a [radir.Map]

Case is not significant in the distinguished name matching process.
*/
func (r *Cache) Registrant(dn string) (entry radir.Entry) {
	switch tv := r.call(dn, "registrant").(type) {
	case *radir.Registrant:
		entry = tv
	case radir.Map:
		entry = tv
	}
	return entry
}

/*
Subentry returns an instance of [radir.Entry] following a search for the
input dn value within the receiver instance.

A nil return value can indicate any of the following:

  - Instance had expired and has since been purged, or has not yet been cached
  - Instance was found but was nil, indicating caching is disabled for the entry
  - Instance was neither a *[radir.Subentry] nor a [radir.Map]

Case is not significant in the distinguished name matching process.
*/
func (r *Cache) Subentry(dn string) (entry radir.Entry) {
	switch tv := r.call(dn, "subentry").(type) {
	case *radir.Subentry:
		entry = tv
	case radir.Map:
		entry = tv
	}
	return entry
}

func (r *Cache) call(dn, typ string) radir.Entry {
	if r.IsZero() {
		return nil
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	isTypeOK := func(item cachedEntry) (ok bool) {
		if item.Value != nil {
			switch tv := item.Value.(type) {
			case *radir.Registration:
				ok = typ == "registration"
			case *radir.Registrant:
				ok = typ == "registrant"
			case *radir.Subentry:
				ok = typ == "subentry"
			case radir.Map:
				// map could represent any of the above,
				// so we check the objectClass []string
				// type to examine whether a class name
				// matches 'typ'.
				if oc, found := tv.StringsValue(`objectClass`); found {
					ok = strInSlice(typ, oc)
				}
			}
		}
		return
	}

	idx := lc(dn)
	item, ok := r.entries[idx]
	if ok && isTypeOK(item) {
		if time.Now().After(item.Expiry) {
			r.delete(idx)
			return nil
		}
	}

	return item.Value
}

/*
Exists returns a Boolean value indicative of whether the specified
distinguished name was found within the receiver instance and was
associated with a particular [radir.Entry] instance.

Case is not significant in the distinguished name matching process.

This method does not take expiration into account, nor does its
use trigger any expiration purges.
*/
func (r *Cache) Exists(dn string) (exists bool) {
	if !r.IsZero() {
		r.lock.Lock()
		defer r.lock.Unlock()

		_, exists = r.entries[lc(dn)]
	}
	return
}

/*
Kind returns the string literals "subentry", "registration" or
"registrant" based on the kind of entry associated with the
input distinguished name value.

Case is not significant in the distinguished name matching process.

This method does not take expiration into account, nor does its
use trigger any expiration purges.

The string literal "invalid" may also be returned if the receiver
instance is in an abberant state.
*/
func (r *Cache) Kind(dn string) (kind string) {
	kind = "invalid"

	if !r.IsZero() {
		if item, ok := r.entries[lc(dn)]; ok {
			switch tv := item.Value.(type) {
			case *radir.Subentry:
				kind = "subentry"
			case *radir.Registration:
				kind = "registration"
			case *radir.Registrant:
				kind = "registrant"
			case radir.Map:
				if tv.Registration() {
					kind = "registration"
				} else if tv.Registrant() {
					kind = "registrant"
				} else if tv.Subentry() {
					kind = "subentry"
				}
			}
		}
	}

	return
}

/*
Keys returns slices of cached element DNs, each representing a
[radir.Entry] instance present within the receiver.

This method does not take expiration into account, nor does its
use trigger any expiration purges.
*/
func (r *Cache) Keys() (keys []string) {
	if !r.IsZero() {

		r.lock.Lock()
		defer r.lock.Unlock()

		for _, v := range r.entries {
			if dn := v.Value.DN(); len(dn) > 0 {
				keys = append(keys, dn)
			}
		}
	}

	return
}

/*
Touch will refresh the targeted [radir.Entry] instance by the input dn value,
and replace its Expiry struct field with a fresh [time.Time] instance based
upon the input minutes value, which may be a string or an int.

In addition to preserving instances past their original expiration time,
this method may be used to "resurrect" instances that have since expired
but have not yet been purged from the receiver instance.

This method has no effect if the targeted instance is not found, the receiver
is zero, or the minutes value is <= 0. If no minutes value is provided at all,
the TTL is derived from the entry -- COLLECTIVE is obtained first, if set. If
an expicit TTL is found in the entry, it supersedes any COLLECTIVE value.
Finally, if no TTL was found anywhere, [DefaultRATTL] is used as a fallback.
*/
func (r *Cache) Touch(dn string, minutes ...any) {
	if r.writable() && len(dn) > 0 {
		r.lock.Lock()
		defer r.lock.Unlock()

		if item, _ := r.entries[lc(dn)]; item.Value != nil {
			item.Expiry = newExpiry(radir.TTLPrecedenceFromEntry(item.Value, minutes...))
		}
	}
}

/*
Add assigns the input [radir.Entry] instance to the receiver instance. The
minutes input value (which may be a string or an int) should correspond to
one of the following states:

  - <=0 (entry default) indicates no caching for the indicated instance (always call LDAP)
  - All other positive values indicate a cached lifespan in minutes (cache and don't call LDAP for this entry until N minutes)

If the target instance is already cached, it shall be replaced with the
input instance, and will be subject to the new lifespan value. This will
achieve the same outcome as use of [Cache.Touch].

This method is meant for use either of the following scenarios:

  - Automatically, whereby an 'rATTL' or 'c-rATTL' value has been set within the RA DIT or the entry itself, and is being observed following retrieval one or more LDAP entries to be marshaled
  - Manually, whereby an instance crafted by the user is being deliberately cached, whether or not LDAP is presently involved

Input instances may be cached at any point, whether modified or not, provided
the receiver instance is not in a frozen or nil state.
*/
func (r *Cache) Add(entry radir.Entry, minutes ...any) {
	if r.writable() {
		if entry != nil && len(entry.DN()) > 0 {
			r.cache(entry, radir.TTLPrecedenceFromEntry(entry, minutes...))
		}
	}
}

/*
Update replaces the specified [radir.Entry] instance in the receiver with
a newer copy without modifying its current TTL. If the entry is expired,
this method will do nothing.

Use of this method will not have any effect if the receiver is currently
frozen or nil.
*/
func (r *Cache) Update(entry radir.Entry) {
	if r.writable() {
		dn := lc(entry.DN())
		if item, found := r.entries[dn]; found && !r.Expired(dn) {
			item.Value = entry
			r.entries[dn] = item
		}
	}
}

/*
Remove deletes the specified [radir.Entry] instance from the receiver
instance.

Case is not significant in the distinguished name matching process.
*/
func (r *Cache) Remove(dn ...string) {
	if len(dn) == 0 || !r.writable() {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.delete(dn...)
}

func (r *Cache) full() bool {
	return r.threshold <= len(r.entries) && r.threshold != 0
}

func (r *Cache) writable() bool { return !(r.IsZero() || r.Frozen()) }

func (r *Cache) cache(entry radir.Entry, minutes int) {
	if !r.Exists(entry.DN()) {
		// reg is not presently cached.
		if r.full() {
			// cannot cache: full house
			return
		}
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	r.entries[lc(entry.DN())] = cachedEntry{
		Value:  entry,
		Expiry: newExpiry(minutes),
	}
}

/*
Freeze freezes the receiver instance, thereby preventing any subsequent
updates and clean-ups from proceeding. This means no expirations (removals)
of expired cache entries will occur, nor can any new elements be added to
the instance. Cached elements may still be accessed using conventional means.

See the [Cache.Thaw] method for a means of unfreezing the receiver instance.
See the [Cache.Frozen] method for a means of confirming a frozen or thawed
state.

Note that the receiver can still be freed (destroyed) by [Cache.Free]
while frozen.
*/
func (r *Cache) Freeze() {
	if r.writable() {
		r.lock.Lock()
		defer r.lock.Unlock()

		r.frozen = true
	}
}

/*
Thaw unfreezes the receiver instance, thereby allowing any subsequent
updates and clean-ups to proceed. This means that expirations (removals)
of expired cache entries will occur, and new elements may be added to
the instance.

See the [Cache.Freeze] method for a means of freezing the receiver instance.
See the [Cache.Frozen] method for a means of confirming a frozen state.
*/
func (r *Cache) Thaw() {
	if !r.IsZero() && r.Frozen() {
		r.lock.Lock()
		defer r.lock.Unlock()

		r.frozen = false
	}
}

/*
Frozen returns a Boolean value indicative of a frozen receiver state.
During a freeze state, no new elements may be added to the instance,
nor can expired elements be purged.

Note that the receiver can still be freed (destroyed) by [Cache.Free]
while frozen.
*/
func (r *Cache) Frozen() bool {
	return r.frozen
}

/*
Free frees (destroys) the *[Cache] instance, rendering it nil and unusable.

Note that this method is immutable, and will not honor any frozen state or
mutex lock.
*/
func (r *Cache) Free() {
	*r = Cache{}
}

/*
Flush will purge ALL cached entries from the receiver, regardless
of expiration status, and returns an integer value indicating the
number of entries removed. Following completion, the receiver
remains initialized and usable.
*/
func (r *Cache) Flush() int {
	return r.flush(true)
}

/*
Tidy scans for, and purges the receiver instance of all entries which
have expired, and returns an integer value indicating the number of
entries removed.
*/
func (r *Cache) Tidy() int {
	return r.flush(false)
}

func (r *Cache) flush(all bool) (count int) {
	if !r.writable() {
		return
	}

	r.lock.Lock()
	defer r.lock.Unlock()

	for k, v := range r.entries {
		if time.Now().After(v.Expiry) || all {
			r.delete(k)
			count++
		}
	}

	return
}

func (r *Cache) delete(dn ...string) {
	if !r.Frozen() {
		for _, x := range dn {
			delete(r.entries, lc(x))
		}
	}
}

/*
newExpiry returns an instance of [time.Time] that defines when a given
item will be considered expired and needing refresh.
*/
func newExpiry(m int) time.Time {
	return time.Now().Add(time.Duration(m) * time.Minute)
}

/*
Dump returns an error following an attempt to write the current contents
of the receiver instance to the filename indicated.
*/
func (r *Cache) Dump(filename string) (err error) {
	if !r.IsZero() {
		var file *os.File
		if file, err = os.Create(filename); err == nil {
			defer file.Close()
			err = gob.NewEncoder(file).Encode(r.entries)
		}
	}
	return
}

/*
Load returns an error following an attempt to read the filename indicated
into the receiver instance.
*/
func (r *Cache) Load(filename string) error {
	if !r.writable() {
		return unwritableCacheErr
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	codec := gob.NewDecoder(file)
	return codec.Decode(&r.entries)
}

var (
	unwritableCacheErr error = errors.New("Cache is uninitialized or frozen")
)
