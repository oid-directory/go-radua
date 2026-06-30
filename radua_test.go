package radua

import (
	//"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/oid-directory/go-radir"
)

func TestCache_Registration_offline(t *testing.T) {
	cache := NewCache(0)

	// create a profile
	cfg := radir.NewFactoryDefaultDUAConfig()

	// Hand-crafted registrant
	me := cfg.Profile().NewRegistrant()
	me.SetDN("cn=Jesse Coretta,ou=Registrants,o=rA")
	me.FirstAuthority().SetCN("Jesse Coretta")
	me.FirstAuthority().SetC("US")
	me.FirstAuthority().SetST("California")
	me.FirstAuthority().SetEmail("jesse.coretta@icloud.com")

	// Hand-crafted registration
	myReg := cfg.Profile().NewRegistration()
	myReg.SetDN("n=999,n=56521,n=1,n=4,n=1,n=6,n=3,n=1,ou=Registrations,o=rA")
	myReg.SetTTL(5)
	myReg.X680().SetN("999")
	myReg.X680().SetIdentifier("example")
	myReg.X680().SetDotNotation("1.3.6.1.4.1.56521.999")
	myReg.X680().SetASN1Notation("{iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) 56521 example(999)}")
	myReg.X660().SetFirstAuthorities(me.DN())

	myReg.NewChild("10", "test")
	myReg.NewChild("11", "question")

	// Add above registration and registrant to cache for five minutes.
	cache.Add(myReg, 5)
	cache.Add(me, 5)

	// Call the DN from the cache as a Registration.
	cached := cache.Registration(myReg.DN()).(*radir.Registration)

	// Check its what we expected ...
	if nf := cached.X680().N(); nf != "999" {
		t.Errorf("%s failed:\n\twant: '%s'\n\tgot:  '%s'", t.Name(), "999", nf)
		return
	}

	t.Logf("%s\n", cached.LDIF(2))
	t.Logf("%s\n", cache.Registrant(cached.X660().FirstAuthorities()[0]).(*radir.Registrant).LDIF())
}

func TestRegistration_Marshal(t *testing.T) {
	entry := &ldap.Entry{
		DN: "n=56521,n=1,n=4,n=1,n=6,n=3,n=1,ou=Registrations,o=rA",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{
				"top",
				"registration",
				"arc",
				"x680Context",
			}},
			{Name: "dotNotation", Values: []string{"1.3.6.1.4.1.56521"}},
			{Name: "n", Values: []string{"56521"}},
			{Name: "aSN1Notation", Values: []string{
				"{iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) 56521}",
			}},
		},
	}

	var reg *radir.Registration = radir.NewFactoryDefaultDUAConfig().Profile().NewRegistration()
	if err := entry.UnmarshalFunc(reg, unmarshalFunc); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}

	t.Logf("\n%s", reg.LDIF(0))

}

//func TestDUA_Read(t *testing.T) {
//
//	conn, err := ldap.Dial("tcp", `localhost:389`)
//	if err != nil {
//		t.Errorf("%s failed: %v", t.Name(), err)
//		return
//	}
//
//	//cache := NewCache(0) // unlimited capacity cache
//
//	conn.Bind(``, ``)
//	defer conn.Unbind()
//
//	//var client *RADUA
//	//if client, err = New(cfg, conn, cache); err != nil {
//	//	t.Errorf("%s failed: %v", t.Name(), err)
//	//	return
//	//}
//
//	subdn := `cn=iso,n=1,ou=Registrations,o=rA`
//        controls := []ldap.Control{
//                ldap.NewControlString(`1.3.6.1.4.1.4203.1.10.1`, false, "y"),
//        }
//
//	sr := ldap.NewSearchRequest(subdn, 0, 0, 0, 0, false, `(objectClass=subentry)`, []string{`*`,`+`}, controls)
//	var res *ldap.SearchResult
//	if res, err = conn.Search(sr); err != nil {
//		fmt.Println(err)
//		return
//	}
//
//	L := len(res.Entries)
//	if L != 1 {
//		fmt.Println("Expected one entry")
//		return
//	}
//
//	entry := res.Entries[0]
//	fmt.Printf("%#v\n", entry)
//
//	//var reg *radir.Registration = cfg.Profile().NewRegistration()
//	//if err = client.Read(`1.3.6.1.4.1.56521`, reg); err != nil {
//	//	t.Errorf("%s failed: %v", t.Name(), err)
//	//	return
//	//}
//}
