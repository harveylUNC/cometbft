package types

import (
	"bytes"
	"fmt"
	"math"
	"sort"
	"strings"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/ed25519"
	cmtrand "github.com/cometbft/cometbft/internal/rand"
	cmtmath "github.com/cometbft/cometbft/libs/math"
)

func createTestValidators() []*Validator {
    return []*Validator{
        {Address: []byte("validator1"), VotingPower: 10},
        {Address: []byte("validator2"), VotingPower: 20},
        {Address: []byte("validator3"), VotingPower: 30},
    }
}

func TestNewValidatorGroup(t *testing.T) {
    validators := createTestValidators()
    group := NewValidatorGroup(1, validators)

    if group == nil {
        t.Fatal("NewValidatorGroup returned nil")
    }

    if group.TotalVotingPower() != 60 {
        t.Errorf("Expected total voting power to be 60, got %d", group.TotalVotingPower())
    }

    if group.GetProposer() == nil {
        t.Error("Proposer should not be nil")
    }
}

func TestGetProposer(t *testing.T) {
    validators := createTestValidators()
    group := NewValidatorGroup(1, validators)
    proposer := group.GetProposer()

    if proposer == nil {
        t.Fatal("GetProposer returned nil")
    }

    fmt.Println("Proposer:", proposer.Address)

    // Additional checks on proposer can be added here
}
func TestValidateBasic(t *testing.T) {
    validators := createTestValidators()
    group := NewValidatorGroup(1, validators)

    if err := group.ValidateBasic(); err != nil {
        t.Errorf("ValidateBasic returned an error: %v", err)
    }
}
