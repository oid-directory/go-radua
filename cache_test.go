package radua

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/oid-directory/go-radir"
)

var myCache *Cache // for go pkg examples

func ExampleCache_Len() {
	myCache.Add(&radir.Registration{R_DN: `dc=example,dc=com`}, 3) // fake search result
	fmt.Println(myCache.Len())
	// Output: 1
}

func ExampleCache_Registration() {
	dn := "n=999,n=56521,n=1,n=4,n=1,n=6,n=3,n=1,ou=Registrations,o=rA"
	example := myCache.Registration(dn) // nonexistent DN call

	fmt.Println(example == nil)
	// Output: true
}

func ExampleCache_Update() {
	// very watered-down registration
	reg := &radir.Registration{
		R_DN: "n=999,n=56521,n=1,n=4,n=1,n=6,n=3,n=1,ou=Registrations,o=rA",
	}

	// Cache the reg for 15 minutes
	myCache.Add(reg, 15)

	// We update our reg (above) with additional information
	// we forgot to add the first time around.
	reg.X680().SetNameAndNumberForm("example(999)")

	// Now we update the copy of the reg in the cache
	// without altering its TTL.
	myCache.Update(reg)

	// Call the new reg from cache (overwriting our local reg var above)
	reg = myCache.Registration("n=999,n=56521,n=1,n=4,n=1,n=6,n=3,n=1,ou=Registrations,o=rA")

	// Check that cache-born reg has the newly added value.
	fmt.Printf("NameAndNumberForm: %q", reg.X680().NameAndNumberForm())
	// Output: NameAndNumberForm: "example(999)"
}

func ExampleCache_Registrant() {
	dn := "cn=Mister Authority,ou=Registrants,o=rA"
	example := myCache.Registrant(dn) // nonexistent DN call

	fmt.Println(example == nil)
	// Output: true
}

func ExampleCache_Touch() {
	dn := "dc=example,dc=com"
	myCache.Touch(dn, 2)
	fmt.Println(myCache.Expired(dn))
	// Output: false
}

func ExampleCache_Cap() {
	// note: cache was initialized with a capacity of 2
	// via NewCache(2).
	fmt.Println(myCache.Cap())
	// Output: 2
}

func TestCache_writes(t *testing.T) {
	// Create a temp file
	tempDir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	defer os.RemoveAll(tempDir)

	var myCache3 *Cache
	myCache2 := NewCache(0, 0)

	fileName := `entry.cache`
	path := filepath.Join(tempDir, fileName)
	myCache3.Load(``)
	myCache3.Load(path)
	myCache3.Freeze()
	myCache3.Load(path)
	myCache3.Write(path)
	myCache2.Freeze()
	myCache2.Write(``)
	myCache2.Write(path)
	myCache2.Load(`a`)
	myCache2.Thaw()
	myCache2.Load(path)
	myCache2.Load(`a`)
}

func TestCache_call(t *testing.T) {
	var c *Cache = NewCache(86400)
	c.Add(&radir.Registrant{R_DN: `fakeAuthy`}, 1)
	if k := c.Kind(`fakeAuthy`); k != `registrant` {
		t.Errorf("%s failed [kind]: expected registrant, got %s", t.Name(), k)
	}
	c.Free()
}

func TestCache_codecov(t *testing.T) {
	var c *Cache
	c.IsZero()
	c.Expired("fargus")
	c.Expired("")
	c.Add(nil, -1)
	c.Add(&ldap.Entry{}, 1)
	c.Add(&ldap.Entry{DN: "fargus"}, 1)
	c.Registration("blarg")
	c.Registrant("blarg")
	c.Kind(`fargus`)
	c.Registration("fargus")
	c.Registrant("fargus")
	c.Flush()
	c.Tidy()
	c.Touch(`blarg`, 1)
	c.Touch(`who`, -1)
	c.Remove(`blarg`)
	c.Remove(``)
	c = NewCache(-5, -1)
	c = NewCache(1, 1)
	fakeR := cachedEntry{
		Value: &radir.Registration{R_DN: "fake"},
	}
	fakeA := cachedEntry{
		Value: &radir.Registrant{R_DN: "fakeAuthy"},
	}
	c.Expired("")
	c.entries[`fake`] = fakeR
	c.entries[`fakeAuthy`] = fakeA
	c.Kind(`fake`)
	c.Kind(`fakeAuthy`)
	c.Touch(``, 5)
	c.Remove()
	c.Add(&ldap.Entry{}, 1)
	c.Registration(`faker`)
	c.Add(&radir.Registration{R_DN: `otherFaker`}, 1)
	c.Kind(`otherFaker`)
	c.Keys()
	c.Kind(`fakeAuthy`)
	c.Tidy()
	c.entries[`fake`] = fakeR
	c.Registration(`fake`)
	c.Flush()
	c.Keys()
	c.Remove(`bob`)
	c.Tidy()
	c.Flush()
	c.Freeze()
	c.Remove(`blarg`)
	c.Free()
}

func init() {
	myCache = NewCache(2)
}
