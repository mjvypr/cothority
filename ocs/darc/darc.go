/*
Package darc in most of our projects we need some kind of access control to protect resources. Instead of having a simple password
or public key for authentication, we want to have access control that can be:
evolved with a threshold number of keys
be delegated
So instead of having a fixed list of identities that are allowed to access a resource, the goal is to have an evolving
description of who is allowed or not to access a certain resource.
*/
package darc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/dedis/cothority"
	"github.com/dedis/cothority/ocs/darc/expression"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/kyber/util/key"
	"github.com/dedis/protobuf"
)

const evolve = "_evolve"

// InitRules initialise a set of rules with only the default action.
func InitRules(owners []*Identity) Rules {
	ids := make([]string, len(owners))
	for i, o := range owners {
		ids[i] = o.String()
	}
	rs := make(Rules)
	rs[evolve] = expression.InitOrExpr(ids)
	return rs
}

// NewDarc initialises a darc-structure given its owners and users
func NewDarc(rules Rules, desc []byte) *Darc {
	return &Darc{
		Version:     0,
		Description: &desc,
		Signature:   nil,
		Rules:       rules,
	}
}

// Copy all the fields of a Darc except the signature
func (d *Darc) Copy() *Darc {
	dCopy := &Darc{
		Version: d.Version,
		BaseID:  d.BaseID,
	}
	if d.Description != nil {
		desc := *(d.Description)
		dCopy.Description = &desc
	}
	newRules := make(Rules)
	for k, v := range d.Rules {
		newRules[k] = v
	}
	dCopy.Rules = newRules
	return dCopy
}

// GetEvolutionExpr returns the expression that describes the evolution action.
func (d Darc) GetEvolutionExpr() expression.Expr {
	return d.Rules[evolve]
}

// Equal returns true if both darcs point to the same data.
func (d *Darc) Equal(d2 *Darc) bool {
	return d.GetID().Equal(d2.GetID())
}

// ToProto returns a protobuf representation of the Darc-structure.
// We copy a darc first to keep only invariant fields which exclude
// the delegation signature.
func (d *Darc) ToProto() ([]byte, error) {
	dc := d.Copy()
	b, err := protobuf.Encode(dc)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// NewDarcFromProto interprets a protobuf-representation of the darc and
// returns a created Darc.
func NewDarcFromProto(protoDarc []byte) *Darc {
	d := &Darc{}
	protobuf.Decode(protoDarc, d)
	return d
}

// GetID returns the hash of the protobuf-representation of the Darc as its Id:
// H(ver + desc + baseID + {action + expr | rules} + H(sig)). The
// rules
// map is orderd by action.
func (d Darc) GetID() ID {
	h := sha256.New()
	verBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(verBytes, d.Version)
	h.Write(verBytes)
	if d.Description != nil {
		h.Write(*d.Description)
	}
	if d.BaseID != nil {
		h.Write(*d.BaseID)
	}

	actions := make([]string, len(d.Rules))
	var i int
	for k := range d.Rules {
		actions[i] = string(k)
		i++
	}
	sort.Strings(actions)
	for _, a := range actions {
		h.Write([]byte(a))
		h.Write(d.Rules[Action(a)])
	}

	if d.Signature != nil {
		sigHash, err := d.Signature.Hash()
		if err != nil {
			panic(err)
		}
		h.Write(sigHash)
	}

	return h.Sum(nil)
}

// GetBaseID returns the base ID or the ID of this darc if its the
// first darc.
func (d *Darc) GetBaseID() ID {
	if d.Version == 0 {
		return d.GetID()
	}
	return *d.BaseID
}

// TODO we need to make sure the user does not delete the evolve action

// AddRule TODO
func (r Rules) AddRule(a Action, expr expression.Expr) error {
	if _, ok := r[a]; ok {
		return errors.New("action already exists")
	}
	r[a] = expr
	return nil
}

// UpdateRule TODO
func (r Rules) UpdateRule(a Action, expr expression.Expr) error {
	if isEvolution(a) {
		return errors.New("cannot update evolution")
	}
	return r.updateRule(a, expr)
}

// DeleteRules TODO
func (r Rules) DeleteRules(a Action) error {
	if isEvolution(a) {
		return errors.New("cannot delete evolution")
	}
	if _, ok := r[a]; !ok {
		return errors.New("action does not exist")
	}
	delete(r, a)
	return nil
}

// UpdateEvolution will update the "evolve" action, which allows identities
// that satisfies the expression to evolve the Darc. Take extreme care when
// using this function.
func (r Rules) UpdateEvolution(expr expression.Expr) error {
	return r.updateRule(evolve, expr)
}

func (r Rules) updateRule(a Action, expr expression.Expr) error {
	if _, ok := r[a]; !ok {
		return errors.New("action does not exist")
	}
	r[a] = expr
	return nil
}

func isEvolution(action Action) bool {
	if action == evolve {
		return true
	}
	return false
}

// SetEvolution evolves a darc, the latest valid darc needs to sign the new
// darc.  Only if one of the previous owners signs off on the new darc will it
// be valid and accepted to sign on behalf of the old darc. The path can be nil
// unless if the previousOwner is an SignerEd25519 and found directly in the
// previous darc.
func (d *Darc) SetEvolution(prevd *Darc, pth *SignaturePath, prevOwner *Signer) error {
	d.Signature = nil
	d.Version = prevd.Version + 1
	if pth == nil {
		pth = &SignaturePath{Darcs: &[]*Darc{prevd}, Signer: *prevOwner.Identity()}
	}
	if prevd.BaseID == nil {
		id := prevd.GetID()
		d.BaseID = &id
	}
	sig, err := NewDarcSignature(d.GetID(), pth, prevOwner)
	if err != nil {
		return errors.New("error creating a darc signature for evolution: " + err.Error())
	}
	if sig != nil {
		d.Signature = sig
	} else {
		return errors.New("the resulting signature is nil")
	}
	return nil
}

// SetEvolutionOnline works like SetEvolution, but doesn't inlcude all the
// necessary data to verify the update in an offline setting. This is enough
// for the use case where the ocs stores all darcs in its internal database.
// The service verifying the signature will have to verify if there is a valid
// path from the previous darc to the signer.
func (d *Darc) SetEvolutionOnline(prevd *Darc, prevOwner *Signer) error {
	d.Signature = nil
	d.Version = prevd.Version + 1
	if prevd.BaseID == nil {
		id := prevd.GetID()
		d.BaseID = &id
	}
	path := &SignaturePath{Signer: *prevOwner.Identity()}
	sig, err := NewDarcSignature(d.GetID(), path, prevOwner)
	if err != nil {
		return errors.New("error creating a darc signature for evolution: " + err.Error())
	}
	if sig != nil {
		d.Signature = sig
	} else {
		return errors.New("the resulting signature is nil")
	}
	return nil
}

// IncrementVersion updates the version number of the Darc
func (d *Darc) IncrementVersion() {
	d.Version++
}

// Verify returns nil if the verification is OK, or an error
// if something is wrong.
func (d Darc) Verify() error {
	if d.Version == 0 {
		return nil
	}
	if d.Signature == nil || len(d.Signature.Signature) == 0 {
		return errors.New("No signature available")
	}
	latest, err := d.GetLatest()
	if err != nil {
		return err
	}
	if err := d.Signature.SignaturePath.Verify(); err != nil {
		return err
	}
	return d.Signature.Verify(d.GetID(), latest)
}

// GetLatest searches for the previous darc in the signature and returns an
// error if it's not an evolving darc.
func (d Darc) GetLatest() (*Darc, error) {
	if d.Signature == nil {
		// signature is nil if there are no evolution - nothing to sign
		return nil, nil
	}
	if d.Signature.SignaturePath.Darcs == nil {
		return nil, errors.New("signature but no darcs")
	}
	prev := (*d.Signature.SignaturePath.Darcs)[0]
	if prev.Version+1 != d.Version {
		return nil, errors.New("not clean evolution - version mismatch")
	}
	return prev, nil
}

// CheckRequest checks the given request and returns an error if it cannot be
// accepted.
func (d Darc) CheckRequest(r *Request) error {
	/*
		if r.Signatures == nil || len(r.Signatures) == 0 {
			return errors.New("no signature in request")
		}
		// TODO do we need to do a GetLatest?
		if !r.ID.Equal(d.GetID()) {
			return fmt.Errorf("identities are not equal, got %s but need %s", r.ID, d.GetID())
		}
		// TODO more verification
	*/
	return nil
}

func (d Darc) String() string {
	s := fmt.Sprintf("this[base]: %x[%x]\nVersion: %d\nRules:", d.GetID(), d.GetBaseID(), d.Version)
	for k, v := range d.Rules {
		s += fmt.Sprintf("\n\t%s - \"%s\"", k, v)
	}
	sigStr := "nil"
	if d.Signature != nil {
		sigStr = "sig"
	}
	s += fmt.Sprintf("\nSignature: %s", sigStr)
	return s
}

// IsNull returns true if this DarcID is not initialised.
func (di ID) IsNull() bool {
	return di == nil
}

// Equal compares with another DarcID.
func (di ID) Equal(other ID) bool {
	return bytes.Equal([]byte(di), []byte(other))
}

// NewDarcSignature creates a new darc signature by hashing (PathMsg + msg),
// where PathMsg is retrieved from a given signature path, and signing it
// with a given signer.
func NewDarcSignature(msg []byte, sigpath *SignaturePath, signer *Signer) (*Signature, error) {
	if sigpath == nil || signer == nil {
		return nil, errors.New("signature path or signer are missing")
	}
	hash, err := sigpath.HashWith(msg)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(hash)
	if err != nil {
		return nil, errors.New("failed to sign a hash")
	}
	return &Signature{Signature: sig, SignaturePath: *sigpath}, nil
}

// Verify returns nil if the signature is correct, or an error
// if something is wrong.
func (ds *Signature) Verify(msg []byte, base *Darc) error {
	if base == nil {
		return errors.New("Base-darc is missing")
	}
	if ds.SignaturePath.Darcs == nil || len(*ds.SignaturePath.Darcs) == 0 {
		return errors.New("No path stored in signaturepath")
	}
	sigBase := (*ds.SignaturePath.Darcs)[0].GetID()
	if !sigBase.Equal(base.GetID()) {
		return errors.New("Base-darc is not at root of path")
	}
	hash, err := ds.SignaturePath.HashWith(msg)
	if err != nil {
		return err
	}
	return ds.SignaturePath.Signer.Verify(hash, ds.Signature)
}

// Hash computes the digest of the Signature struct.
func (ds Signature) Hash() ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(ds.Signature)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(ds.SignaturePath.GetPathMsg())
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// HashWith returns the hash needed to create or verify a DarcSignature.
func (sigpath *SignaturePath) HashWith(msg []byte) ([]byte, error) {
	h := sha256.New()
	msgpath := sigpath.GetPathMsg()
	_, err := h.Write(msgpath)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(msg)
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// GetPathMsg returns the concatenated Darc-IDs of the path.
func (sigpath *SignaturePath) GetPathMsg() []byte {
	if sigpath == nil {
		return []byte{}
	}
	var path []byte
	if sigpath.Darcs == nil {
		path = []byte("online")
	} else {
		for _, darc := range *sigpath.Darcs {
			path = append(path, darc.GetID()...)
		}
	}
	return path
}

// Verify makes sure that the path is a correctly evolving one (each next darc
// should be referenced by the previous one) and that the signer is present in
// the latest darc.
func (sigpath *SignaturePath) Verify() error {
	if len(*sigpath.Darcs) == 0 {
		return errors.New("no path stored")
	}
	var prev *Darc
	// we loop from latest to earliest
	for _, d := range *sigpath.Darcs {
		if d == nil {
			return errors.New("null pointer in path list")
		}
		if prev == nil {
			prev = d
			continue
		}
		latest, err := d.GetLatest()
		if err != nil {
			return err
		}
		// ?? what is this Latest and how can it be nil?
		if latest != nil {
			if err := d.Verify(); err != nil {
				return err
			}
		} else {
			signer := d.Signature.SignaturePath.Signer
			if err := checkEvolutionPermission(&signer, prev.Rules[evolve]); err != nil {
				return err
			}
			// TODO what do we verify here?
			/*
				if err := d.Signature.Verify(prev.Signature.SignaturePath.GetPathMsg(), d.GetBaseID()); err != nil {
					return err
				}
			*/
		}
		prev = d
	}
	return nil
}

// checkEvolutionPermission
func checkEvolutionPermission(id *Identity, expr expression.Expr) error {
	Y := expression.InitParser(func(s string) bool {
		if id.String() == s {
			return true
		}
		return false
	})
	res, err := expression.ParseExpr(Y, expr)
	if err != nil {
		return err
	}
	if res != true {
		return errors.New("expression evaluated to false")
	}
	return nil
}

// Type returns an integer representing the type of key held in the signer.
// It is compatible with Identity.Type. For an empty signer, -1 is returned.
func (s *Signer) Type() int {
	switch {
	case s.Ed25519 != nil:
		return 1
	case s.X509EC != nil:
		return 2
	default:
		return -1
	}
}

// Identity returns an identity struct with the pre initialised fields
// for the appropriate signer.
func (s *Signer) Identity() *Identity {
	switch s.Type() {
	case 1:
		return &Identity{Ed25519: &IdentityEd25519{Point: s.Ed25519.Point}}
	case 2:
		return &Identity{X509EC: &IdentityX509EC{Public: s.X509EC.Point}}
	default:
		return nil
	}
}

// Sign returns a signature in bytes for a given messages by the signer
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	if msg == nil {
		return nil, errors.New("nothing to sign, message is empty")
	}
	switch s.Type() {
	case 0:
		return nil, errors.New("cannot sign with a darc")
	case 1:
		return s.Ed25519.Sign(msg)
	case 2:
		return s.X509EC.Sign(msg)
	default:
		return nil, errors.New("unknown signer type")
	}
}

// GetPrivate returns the private key, if one exists.
func (s *Signer) GetPrivate() (kyber.Scalar, error) {
	switch s.Type() {
	case 1:
		return s.Ed25519.Secret, nil
	case 0, 2:
		return nil, errors.New("signer lacks a private key")
	default:
		return nil, errors.New("signer is of unknown type")
	}
}

// Equal first checks the type of the two identities, and if they match,
// it returns if their data is the same.
func (id *Identity) Equal(id2 *Identity) bool {
	if id.Type() != id2.Type() {
		return false
	}
	switch id.Type() {
	case 0:
		return id.Darc.Equal(id2.Darc)
	case 1:
		return id.Ed25519.Equal(id2.Ed25519)
	case 2:
		return id.X509EC.Equal(id2.X509EC)
	}
	return false
}

// Type returns an int indicating what type of identity this is. If all
// identities are nil, it returns -1.
func (id *Identity) Type() int {
	switch {
	case id.Darc != nil:
		return 0
	case id.Ed25519 != nil:
		return 1
	case id.X509EC != nil:
		return 2
	}
	return -1
}

// TypeString returns the string of the type of the identity.
func (id *Identity) TypeString() string {
	switch id.Type() {
	case 0:
		return "darc"
	case 1:
		return "ed25519"
	case 2:
		return "x509ec"
	default:
		return "No identity"
	}
}

// String returns the string representation of the identity
func (id *Identity) String() string {
	switch id.Type() {
	case 0:
		return fmt.Sprintf("%s:%x", id.TypeString(), id.Darc.ID)
	case 1:
		return fmt.Sprintf("%s:%s", id.TypeString(), id.Ed25519.Point.String())
	case 2:
		return fmt.Sprintf("%s:%x", id.TypeString(), id.X509EC.Public)
	default:
		return "No identity"
	}
}

// Verify returns nil if the signature is correct, or an error if something
// went wrong.
func (id *Identity) Verify(msg, sig []byte) error {
	switch id.Type() {
	case 0:
		return errors.New("cannot verify a darc-signature")
	case 1:
		return id.Ed25519.Verify(msg, sig)
	case 2:
		return id.X509EC.Verify(msg, sig)
	default:
		return errors.New("unknown identity")
	}
}

// NewIdentityDarc creates a new darc identity struct given a darcid
func NewIdentityDarc(id ID) *Identity {
	return &Identity{
		Darc: &IdentityDarc{
			ID: id,
		},
	}
}

// Equal returns true if both IdentityDarcs point to the same data.
func (idd *IdentityDarc) Equal(idd2 *IdentityDarc) bool {
	return bytes.Compare(idd.ID, idd2.ID) == 0
}

// NewIdentityEd25519 creates a new Ed25519 identity struct given a point
func NewIdentityEd25519(point kyber.Point) *Identity {
	return &Identity{
		Ed25519: &IdentityEd25519{
			Point: point,
		},
	}
}

// Equal returns true if both IdentityEd25519 point to the same data.
func (ide *IdentityEd25519) Equal(ide2 *IdentityEd25519) bool {
	return ide.Point.Equal(ide2.Point)
}

// Verify returns nil if the signature is correct, or an error if something
// fails.
func (ide *IdentityEd25519) Verify(msg, sig []byte) error {
	return schnorr.Verify(cothority.Suite, ide.Point, msg, sig)
}

// NewIdentityX509EC creates a new X509EC identity struct given a point
func NewIdentityX509EC(public []byte) *Identity {
	return &Identity{
		X509EC: &IdentityX509EC{
			Public: public,
		},
	}
}

// Equal returns true if both IdentityX509EC point to the same data.
func (idkc *IdentityX509EC) Equal(idkc2 *IdentityX509EC) bool {
	return bytes.Compare(idkc.Public, idkc2.Public) == 0
}

type sigRS struct {
	R *big.Int
	S *big.Int
}

// Verify returns nil if the signature is correct, or an error if something
// fails.
func (idkc *IdentityX509EC) Verify(msg, s []byte) error {
	public, err := x509.ParsePKIXPublicKey(idkc.Public)
	if err != nil {
		return err
	}
	hash := sha512.Sum384(msg)
	sig := &sigRS{}
	_, err = asn1.Unmarshal(s, sig)
	if err != nil {
		return err
	}
	if ecdsa.Verify(public.(*ecdsa.PublicKey), hash[:], sig.R, sig.S) {
		return nil
	}
	return errors.New("Wrong signature")
}

// NewSignerEd25519 initializes a new SignerEd25519 given a public and private keys.
// If any of the given values is nil or both are nil, then a new key pair is generated.
// It returns a signer.
func NewSignerEd25519(point kyber.Point, secret kyber.Scalar) *Signer {
	if point == nil || secret == nil {
		kp := key.NewKeyPair(cothority.Suite)
		point, secret = kp.Public, kp.Private
	}
	return &Signer{Ed25519: &SignerEd25519{
		Point:  point,
		Secret: secret,
	}}
}

// Sign creates a schnorr signautre on the message
func (eds *SignerEd25519) Sign(msg []byte) ([]byte, error) {
	return schnorr.Sign(cothority.Suite, eds.Secret, msg)
}

// NewSignerX509EC creates a new SignerX509EC - mostly for tests
func NewSignerX509EC() *Signer {
	return nil
}

// Sign creates a RSA signature on the message
func (kcs *SignerX509EC) Sign(msg []byte) ([]byte, error) {
	return nil, errors.New("not yet implemented")
}
