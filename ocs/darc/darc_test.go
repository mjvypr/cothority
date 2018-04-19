package darc

import (
	"testing"

	"github.com/dedis/cothority/ocs/darc/expression"
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/require"
)

func TestRules(t *testing.T) {
	// one owner
	owners := []*Identity{createIdentity()}
	rules := InitRules(owners)
	expr, ok := rules[evolve]
	require.True(t, ok)
	require.Equal(t, string(expr), owners[0].String())

	// two owners
	owners = append(owners, createIdentity())
	rules = InitRules(owners)
	expr, ok = rules[evolve]
	require.True(t, ok)
	require.Equal(t, string(expr), owners[0].String()+" | "+owners[1].String())
}

func TestNewDarc(t *testing.T) {
	desc := []byte("mydarc")
	owners := []*Identity{createIdentity()}

	d := NewDarc(InitRules(owners), desc)
	require.Equal(t, desc, d.Description)
	require.Equal(t, string(d.Rules.GetEvolutionExpr()), owners[0].String())
}

func TestDarc_Copy(t *testing.T) {
	// create two darcs
	d1 := createDarc(1, "testdarc1").darc
	err := d1.Rules.AddRule("ocs:write", d1.Rules.GetEvolutionExpr())
	require.Nil(t, err)
	d2 := d1.Copy()

	// modify the first one
	d1.IncrementVersion()
	desc := []byte("testdarc2")
	d1.Description = desc
	err = d1.Rules.UpdateRule("ocs:write", []byte(createIdentity().String()))
	require.Nil(t, err)

	// the two darcs should be different
	require.NotEqual(t, d1.Version, d2.Version)
	require.NotEqual(t, d1.Description, d2.Description)
	require.NotEqual(t, d1.Rules["ocs:write"], d2.Rules["ocs:write"])

	// ID should not change if values are the same
	d2.Description = nil
	d1 = d2.Copy()
	require.Equal(t, d1.GetID(), d2.GetID())
}

func TestAddRule(t *testing.T) {
	// TODO
}

func TestUpdateRule(t *testing.T) {
	// TODO
}

func TestDeleteRule(t *testing.T) {
	// TODO
}

func TestDarc_IncrementVersion(t *testing.T) {
	d := createDarc(1, "testdarc").darc
	previousVersion := d.Version
	d.IncrementVersion()
	require.NotEqual(t, previousVersion, d.Version)
}

// TestDarc_SetEvolution creates two darcs, the first has two owners and the
// second has one. The first darc is to be evolved into the second one.
func TestDarc_SetEvolutionOne(t *testing.T) {
	d := createDarc(2, "testdarc").darc
	log.ErrFatal(d.Verify())
	owner1 := NewSignerEd25519(nil, nil)
	owner2 := NewSignerEd25519(nil, nil)
	owner3 := NewSignerEd25519(nil, nil)
	id1 := *owner1.Identity()
	id2 := *owner2.Identity()
	// id3 := *owner3.Identity()
	require.Nil(t, d.Rules.UpdateEvolution(expression.InitOrExpr([]string{id1.String(), id2.String()})))

	dNew := d.Copy()
	dNew.IncrementVersion()
	require.Nil(t, dNew.Rules.UpdateEvolution([]byte(id1.String())))
	// verification should fail because the signature path is not present
	require.NotNil(t, dNew.Verify())

	darcs := []*Darc{d}
	// the identity of the signer cannot be id3, it does not have the
	// evolve permission
	require.Nil(t, dNew.Evolve(darcs, owner3))
	require.NotNil(t, dNew.Verify())
	//
	require.Nil(t, dNew.Evolve(darcs, owner2))
	require.Nil(t, dNew.Verify())
	//
	require.Nil(t, dNew.Evolve(darcs, owner1))
	require.Nil(t, dNew.Verify())
	/*
		require.Nil(t, dNew.SetEvolution(d, NewSignaturePath(darcs, *ownerI2, User), owner2))
		assert.NotNil(t, dNew.Verify())
		require.Nil(t, dNew.SetEvolution(d, NewSignaturePath(darcs, *ownerI, User), owner2))
		assert.NotNil(t, dNew.Verify())
		require.Nil(t, dNew.SetEvolution(d, NewSignaturePath(darcs, *ownerI, User), owner))
		require.Nil(t, dNew.Verify())
	*/
}

/*
func TestSignatureChange(t *testing.T) {
	td1 := createDarc("testdarc")
	td2 := createDarc("testdarc")
	td2.darc.SetEvolution(td1.darc, nil, td1.owners[0])
	require.Nil(t, td2.darc.Verify())
	td2.darc.AddUser(td2.usersI[1])
	require.NotNil(t, td2.darc.Verify())

	td2.darc.SetEvolution(td1.darc, nil, td1.owners[0])
	require.Nil(t, td2.darc.Verify())

	td2.darc.AddOwner(td2.ownersI[1])
	require.NotNil(t, td2.darc.Verify())
}

func TestSignaturePath(t *testing.T) {
	td1 := createDarc("testdarc")
	td2 := createDarc("testdarc2")
	td3 := createDarc("testdarc3")
	td4 := createDarc("testdarc4")
	path := NewSignaturePath([]*Darc{td1.darc, td2.darc, td3.darc, td4.darc}, *td4.usersI[0], User)
	require.NotNil(t, path.Verify(User))
	td2.darc.SetEvolution(td1.darc, nil, td1.owners[0])
	td4.darc.SetEvolution(td3.darc, nil, td3.owners[0])
	require.NotNil(t, path.Verify(User))

	td2.darc.AddUser(&Identity{Darc: &IdentityDarc{td3.darc.GetID()}})
	require.NotNil(t, path.Verify(User))
	td2.darc.SetEvolution(td1.darc, nil, td1.owners[0])
	require.Nil(t, path.Verify(User))
	td4.darc.SetEvolution(td3.darc, nil, td3.owners[0])
	require.Nil(t, path.Verify(User))
}

func TestDarcSignature_Verify(t *testing.T) {
	msg := []byte("document")
	d := createDarc("testdarc").darc
	owner := NewSignerEd25519(nil, nil)
	ownerI := owner.Identity()
	path := NewSignaturePath([]*Darc{d}, *ownerI, User)
	ds, err := NewDarcSignature(msg, path, owner)
	log.ErrFatal(err)
	d2 := d.Copy()
	d2.IncrementVersion()
	require.NotNil(t, ds.Verify(msg, d2))
	require.Nil(t, ds.Verify(msg, d))
}

func TestSignature(t *testing.T) {
	// msg := []byte("darc-policy")
	// sigEd := NewSignerEd25519(nil, nil)
	// sig := sigEd.Sign
}
*/

type testDarc struct {
	darc    *Darc
	owners  []*Signer
	ownersI []*Identity
}

func createDarc(nbrOwners int, desc string) *testDarc {
	td := &testDarc{}
	for i := 0; i < nbrOwners; i++ {
		s, id := createSignerIdentity()
		td.owners = append(td.owners, s)
		td.ownersI = append(td.ownersI, id)
	}
	rules := InitRules(td.ownersI)
	td.darc = NewDarc(rules, []byte(desc))
	return td
}

func createSigner() *Signer {
	s, _ := createSignerIdentity()
	return s
}

func createIdentity() *Identity {
	_, id := createSignerIdentity()
	return id
}

func createSignerIdentity() (*Signer, *Identity) {
	signer := NewSignerEd25519(nil, nil)
	return signer, signer.Identity()
}
