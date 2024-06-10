package types

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"

	//TO-DO modify cmtproto to support validatorgroups
	cmtproto "github.com/harveylUNC/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/crypto/merkle"
)

// ValidatorGroup represents group of validators
type ValidatorGroup struct {
	GroupID				int64
	Validators			[]*Validator `json:"validators"`
	Proposer			*Validator `json:"proposer"`
	totalVotingPower	int64
}

// NewValidatorGroup creates a new ValidatorGroup with the given ID and validators.
func NewValidatorGroup(groupID int, validators []*Validator) *ValidatorGroup {
	group := &ValidatorGroup{
		GroupID:    int64(groupID),
		Validators: validators,
	}
	group.updateTotalVotingPower()
	return group
}

func (valg *ValidatorGroup) ValidateBasic() error {
	if valg.IsNilOrEmpty() {
		return errors.New("validator group is nil or empty")
	}

	for idx, val := range valg.Validators {
		if err := val.ValidateBasic(); err != nil {
			return fmt.Errorf("invalid validator #%d: %w", idx, err)
		}
	}

	if err := valg.Proposer.ValidateBasic(); err != nil {
		return fmt.Errorf("proposer failed validate basic, error: %w", err)
	}

	return nil
}

// IsNilOrEmpty returns true if validator group is nil or empty.
func (valg *ValidatorGroup) IsNilOrEmpty() bool {
	return valg == nil || len(valg.Validators) == 0
}

// CopyIncrementProposerPriority increments ProposerPriority and updates the
// proposer on a copy, and returns it.
func (valg *ValidatorGroup) CopyIncrementProposerPriority(times int32) *ValidatorGroup {
	cp := valg.Copy()
	cp.IncrementProposerPriority(times)
	return cp
}

// IncrementProposerPriority increments ProposerPriority of each validator and
// updates the proposer. Panics if validator group is empty.
// `times` must be positive.
func (valg *ValidatorGroup) IncrementProposerPriority(times int32) {
	if valg.IsNilOrEmpty() {
		panic("empty validator group")
	}
	if times <= 0 {
		panic("Cannot call IncrementProposerPriority with non-positive times")
	}

	// Cap the difference between priorities to be proportional to 2*totalPower by
	// re-normalizing priorities, i.e., rescale all priorities by multiplying with:
	//  2*totalVotingPower/(maxPriority - minPriority)
	diffMax := PriorityWindowSizeFactor * valg.TotalVotingPower()
	valg.RescalePriorities(diffMax)
	valg.shiftByAvgProposerPriority()

	var proposer *Validator
	// Call IncrementProposerPriority(1) times times.
	for i := int32(0); i < times; i++ {
		proposer = valg.incrementProposerPriority()
	}

	valg.Proposer = proposer
}

// RescalePriorities rescales the priorities such that the distance between the
// maximum and minimum is smaller than `diffMax`. Panics if validator group is
// empty.
func (valg *ValidatorGroup) RescalePriorities(diffMax int64) {
	if valg.IsNilOrEmpty() {
		panic("empty validator group")
	}
	// NOTE: This check is merely a sanity check which could be
	// removed if all tests would init. voting power appropriately;
	// i.e. diffMax should always be > 0
	if diffMax <= 0 {
		return
	}

	// Calculating ceil(diff/diffMax):
	// Re-normalization is performed by dividing by an integer for simplicity.
	// NOTE: This may make debugging priority issues easier as well.
	diff := computeMaxMinPriorityDiffG(valg)
	ratio := (diff + diffMax - 1) / diffMax
	if diff > diffMax {
		for _, val := range valg.Validators {
			val.ProposerPriority /= ratio
		}
	}
}

func (valg *ValidatorGroup) incrementProposerPriority() *Validator {
	for _, val := range valg.Validators {
		// Check for overflow for sum.
		newPrio := safeAddClip(val.ProposerPriority, val.VotingPower)
		val.ProposerPriority = newPrio
	}
	// Decrement the validator with most ProposerPriority.
	mostest := valg.getValWithMostPriority()
	// Mind the underflow.
	mostest.ProposerPriority = safeSubClip(mostest.ProposerPriority, valg.TotalVotingPower())

	return mostest
}

// computeAvgProposerPriorityG should not be called on an empty validator group.
func (valg *ValidatorGroup) computeAvgProposerPriorityG() int64 {
	n := int64(len(valg.Validators))
	sum := big.NewInt(0)
	for _, val := range valg.Validators {
		sum.Add(sum, big.NewInt(val.ProposerPriority))
	}
	avg := sum.Div(sum, big.NewInt(n))
	if avg.IsInt64() {
		return avg.Int64()
	}

	// This should never happen: each val.ProposerPriority is in bounds of int64.
	panic(fmt.Sprintf("Cannot represent avg ProposerPriority as an int64 %v", avg))
}

// computeMaxMinPriorityDiffG computes the difference between the max and min
// ProposerPriority of that set.
func computeMaxMinPriorityDiffG(valg *ValidatorGroup) int64 {
	if valg.IsNilOrEmpty() {
		panic("empty validator group")
	}
	max := int64(math.MinInt64)
	min := int64(math.MaxInt64)
	for _, v := range valg.Validators {
		if v.ProposerPriority < min {
			min = v.ProposerPriority
		}
		if v.ProposerPriority > max {
			max = v.ProposerPriority
		}
	}
	diff := max - min
	if diff < 0 {
		return -1 * diff
	}
	return diff
}

func (valg *ValidatorGroup) getValWithMostPriority() *Validator {
	var res *Validator
	for _, val := range valg.Validators {
		res = res.CompareProposerPriority(val)
	}
	return res
}

func (valg *ValidatorGroup) shiftByAvgProposerPriority() {
	if valg.IsNilOrEmpty() {
		panic("empty validator group")
	}
	avgProposerPriority := valg.computeAvgProposerPriorityG()
	for _, val := range valg.Validators {
		val.ProposerPriority = safeSubClip(val.ProposerPriority, avgProposerPriority)
	}
}

// validatorListCopyG makes a copy of the validator list.
func validatorListCopyG(valgList []*Validator) []*Validator {
	if valgList == nil {
		return nil
	}
	valgCopy := make([]*Validator, len(valgList))
	for i, val := range valgList {
		valgCopy[i] = val.Copy()
	}
	return valgCopy
}

// Copy each validator into a new ValidatorGroup.
func (valg *ValidatorGroup) Copy() *ValidatorGroup {
	return &ValidatorGroup{
		GroupID:		  valg.GroupID,
		Validators:       validatorListCopyG(valg.Validators),
		Proposer:         valg.Proposer,
		totalVotingPower: valg.totalVotingPower,
	}
}

// HasAddress returns true if address given is in the validator group, false -
// otherwise.
func (valg *ValidatorGroup) HasAddress(address []byte) bool {
	for _, val := range valg.Validators {
		if bytes.Equal(val.Address, address) {
			return true
		}
	}
	return false
}

// GetByAddress returns an index of the validator with address and validator
// itself (copy) if found. Otherwise, -1 and nil are returned.
func (valg *ValidatorGroup) GetByAddress(address []byte) (index int32, val *Validator) {
	i, val := valg.GetByAddressMut(address)
	if i == -1 {
		return -1, nil
	}
	return i, val.Copy()
}

// GetByAddressMut returns an index of the validator with address and the
// direct validator object if found. Mutations on this return value affect the validator group.
// This method should be used by callers who will not mutate Val.
// Otherwise, -1 and nil are returned.
func (valg *ValidatorGroup) GetByAddressMut(address []byte) (index int32, val *Validator) {
	for idx, val := range valg.Validators {
		if bytes.Equal(val.Address, address) {
			return int32(idx), val
		}
	}
	return -1, nil
}

// GetByIndex returns the validator's address and validator itself (copy) by
// index.
// It returns nil values if index is less than 0 or greater or equal to
// len(ValidatorGroup.Validators).
func (valg *ValidatorGroup) GetByIndex(index int32) (address []byte, val *Validator) {
	if index < 0 || int(index) >= len(valg.Validators) {
		return nil, nil
	}
	val = valg.Validators[index]
	return val.Address, val.Copy()
}

// Size returns the length of the validator group.
func (valg *ValidatorGroup) Size() int {
	return len(valg.Validators)
}

// updateTotalVotingPower calculates and updates the total voting power of the group.
func (valg *ValidatorGroup) updateTotalVotingPower() {
	sum := int64(0)
	for _, val := range valg.Validators {
		// mind overflow
		sum = safeAddClip(sum, val.VotingPower)
		if sum > MaxTotalVotingPower {
			panic(fmt.Sprintf(
				"Total voting power should be guarded to not exceed %v; got: %v",
				MaxTotalVotingPower,
				sum))
		}
	}

	valg.totalVotingPower = sum
}

// TotalVotingPower returns the total voting power of the group.
// It recomputes the total voting power if required.
func (valg *ValidatorGroup) TotalVotingPower() int64 {
	if valg.totalVotingPower == 0 {
		valg.updateTotalVotingPower()
	}
	return valg.totalVotingPower
}

// GetProposer returns the current proposer. If the validator group is empty, nil
// is returned.
func (valg *ValidatorGroup) GetProposer() (proposer *Validator) {
	if len(valg.Validators) == 0 {
		return nil
	}
	if valg.Proposer == nil {
		valg.Proposer = valg.findProposer()
	}
	return valg.Proposer.Copy()
}

func (valg *ValidatorGroup) findProposer() *Validator {
	var proposer *Validator
	for _, val := range valg.Validators {
		if proposer == nil || !bytes.Equal(val.Address, proposer.Address) {
			proposer = proposer.CompareProposerPriority(val)
		}
	}
	return proposer
}

// Hash returns the Merkle root hash build using validators (as leaves) in the
// set.
func (valg *ValidatorGroup) Hash() []byte {
	bzs := make([][]byte, len(valg.Validators))
	for i, val := range valg.Validators {
		bzs[i] = val.Bytes()
	}
	return merkle.HashFromByteSlices(bzs)
}

// Iterate will run the given function over the set.
func (valg *ValidatorGroup) Iterate(fn func(index int, val *Validator) bool) {
	for i, val := range valg.Validators {
		stop := fn(i, val.Copy())
		if stop {
			break
		}
	}
}

// processChangesG checks changes against duplicates,
// splits the changes in updates and
// removalg, sorts them by address.
//
// Returns:
// updates, removalg - the sorted lists of updates and removalg
// err - non-nil if duplicate entries or entries with negative voting power are seen
//
// No changes are made to 'origChanges'.
func processChangesG(origChanges []*Validator) (updates, removals []*Validator, err error) {
    // Make a deep copy of the changes and sort by address.
    changes := validatorListCopy(origChanges)
    valGroup := &ValidatorGroup{Validators: changes}
    sort.Sort(ValidatorsByAddressG{Group: valGroup})

    removals = make([]*Validator, 0, len(changes))
    updates = make([]*Validator, 0, len(changes))
    var prevAddr Address

    // Scan changes by address and append valid validators to updates or removals lists.
    for _, valUpdate := range changes {
        if bytes.Equal(valUpdate.Address, prevAddr) {
            err = fmt.Errorf("duplicate entry %v in %v", valUpdate, changes)
            return nil, nil, err
        }

        switch {
        case valUpdate.VotingPower < 0:
            err = fmt.Errorf("voting power can't be negative: %d", valUpdate.VotingPower)
            return nil, nil, err
        case valUpdate.VotingPower > MaxTotalVotingPower:
            err = fmt.Errorf("to prevent clipping/overflow, voting power can't be higher than %d, got %d",
                MaxTotalVotingPower, valUpdate.VotingPower)
            return nil, nil, err
        case valUpdate.VotingPower == 0:
            removals = append(removals, valUpdate)
        default:
            updates = append(updates, valUpdate)
        }

        prevAddr = valUpdate.Address
    }

    return updates, removals, err
}
// verifyUpdatesG verifies a list of updates against a validator group, making sure the allowed
// total voting power would not be exceeded if these updates would be applied to the group.
//
// Inputs:
// updates - a list of proper validator changes, i.e. they have been verified by processChangesG for duplicates
//
//	and invalid values.
//
// valg - the original validator group. Note that valg is NOT modified by this function.
// removedPower - the total voting power that will be removed after the updates are verified and applied.
//
// Returns:
// tvpAfterUpdatesBeforeRemovalg -  the new total voting power if these updates would be applied without the removalg.
//
//	Note that this will be < 2 * MaxTotalVotingPower in case high power validators are removed and
//	validators are added/ updated with high power values.
//
// err - non-nil if the maximum allowed total voting power would be exceeded.
func verifyUpdatesG(
	updates []*Validator,
	valg *ValidatorGroup,
	removedPower int64,
) (tvpAfterUpdatesBeforeRemovalg int64, err error) {
	delta := func(update *Validator, valg *ValidatorGroup) int64 {
		_, val := valg.GetByAddressMut(update.Address)
		if val != nil {
			return update.VotingPower - val.VotingPower
		}
		return update.VotingPower
	}

	updatesCopy := validatorListCopyG(updates)
	sort.Slice(updatesCopy, func(i, j int) bool {
		return delta(updatesCopy[i], valg) < delta(updatesCopy[j], valg)
	})

	tvpAfterRemovalg := valg.TotalVotingPower() - removedPower
	for _, upd := range updatesCopy {
		tvpAfterRemovalg += delta(upd, valg)
		if tvpAfterRemovalg > MaxTotalVotingPower {
			return 0, ErrTotalVotingPowerOverflow
		}
	}
	return tvpAfterRemovalg + removedPower, nil
}

func numNewValidatorsG(updates []*Validator, valg *ValidatorGroup) int {
	numNewValidatorsG := 0
	for _, valUpdate := range updates {
		if !valg.HasAddress(valUpdate.Address) {
			numNewValidatorsG++
		}
	}
	return numNewValidatorsG
}

// computeNewPrioritiesG computes the proposer priority for the validators not present in the group based on
// 'updatedTotalVotingPower'.
// Leaves unchanged the priorities of validators that are changed.
//
// 'updates' parameter must be a list of unique validators to be added or updated.
//
// 'updatedTotalVotingPower' is the total voting power of a group where all updates would be applied but
//
//	not the removalg. It must be < 2*MaxTotalVotingPower and may be close to this limit if close to
//	MaxTotalVotingPower will be removed. This is still safe from overflow since MaxTotalVotingPower is maxInt64/8.
//
// No changes are made to the validator group 'valg'.
func computeNewPrioritiesG(updates []*Validator, valg *ValidatorGroup, updatedTotalVotingPower int64) {
	for _, valUpdate := range updates {
		address := valUpdate.Address
		_, val := valg.GetByAddressMut(address)
		if val == nil {
			// add val
			// Set ProposerPriority to -C*totalVotingPower (with C ~= 1.125) to make sure validators can't
			// un-bond and then re-bond to reset their (potentially previously negative) ProposerPriority to zero.
			//
			// Contract: updatedVotingPower < 2 * MaxTotalVotingPower to ensure ProposerPriority does
			// not exceed the bounds of int64.
			//
			// Compute ProposerPriority = -1.125*totalVotingPower == -(updatedVotingPower + (updatedVotingPower >> 3)).
			valUpdate.ProposerPriority = -(updatedTotalVotingPower + (updatedTotalVotingPower >> 3))
		} else {
			valUpdate.ProposerPriority = val.ProposerPriority
		}
	}
}

// Merges the valg' validator list with the updates list.
// When two elements with same address are seen, the one from updates is selected.
// Expects updates to be a list of updates sorted by address with no duplicates or errors,
// must have been validated with verifyUpdatesG() and priorities computed with computeNewPrioritiesG().
func (valg *ValidatorGroup) applyUpdatesG(updates []*Validator) {
    existing := valg.Validators
    sort.Sort(ValidatorsByAddressG{Group: &ValidatorGroup{Validators: existing}})

    merged := make([]*Validator, len(existing)+len(updates))
    i := 0

    for len(existing) > 0 && len(updates) > 0 {
        if bytes.Compare(existing[0].Address, updates[0].Address) < 0 { // unchanged validator
            merged[i] = existing[0]
            existing = existing[1:]
        } else {
            // Apply add or update.
            merged[i] = updates[0]
            if bytes.Equal(existing[0].Address, updates[0].Address) {
                // Validator is present in both, advance existing.
                existing = existing[1:]
            }
            updates = updates[1:]
        }
        i++
    }

    // Add the elements which are left.
    for j := 0; j < len(existing); j++ {
        merged[i] = existing[j]
        i++
    }
    // OR add updates which are left.
    for j := 0; j < len(updates); j++ {
        merged[i] = updates[j]
        i++
    }

    valg.Validators = merged[:i]
}

// verifyRemovalG checks that the validators to be removed are part of the
// validator group.
// No changes are made to the validator group 'valg'.
func verifyRemovalG(deletes []*Validator, valg *ValidatorGroup) (votingPower int64, err error) {
	removedVotingPower := int64(0)
	for _, valUpdate := range deletes {
		address := valUpdate.Address
		_, val := valg.GetByAddressMut(address)
		if val == nil {
			return removedVotingPower, fmt.Errorf("failed to find validator %X to remove", address)
		}
		removedVotingPower += val.VotingPower
	}
	if len(deletes) > len(valg.Validators) {
		panic("more deletes than validators")
	}
	return removedVotingPower, nil
}

// applyRemovalsG removes the validators specified in 'deletes' from validator
// group 'valg'.
// Should not fail as verification has been done before.
// Expects vals to be sorted by address (done by applyUpdatesG).
func (valg *ValidatorGroup) applyRemovalsG(deletes []*Validator) {
	existing := valg.Validators

	merged := make([]*Validator, len(existing)-len(deletes))
	i := 0

	// Loop over deletes until we removed all of them.
	for len(deletes) > 0 {
		if bytes.Equal(existing[0].Address, deletes[0].Address) {
			deletes = deletes[1:]
		} else { // Leave it in the resulting slice.
			merged[i] = existing[0]
			i++
		}
		existing = existing[1:]
	}

	// Add the elements which are left.
	for j := 0; j < len(existing); j++ {
		merged[i] = existing[j]
		i++
	}

	valg.Validators = merged[:i]
}


// updateWithChangeGroup is the main function used by UpdateWithChangeGroup(
// ) and NewValidatorGroup().
// If 'allowDeletes' is false then delete operations (identified by validators with voting power 0)
// are not allowed and will trigger an error if present in 'changes'.
// The 'allowDeletes' flag is set to false by NewValidatorGroup() and to true by UpdateWithChangeGroup().
func (valg *ValidatorGroup) updateWithChangeGroup(changes []*Validator, allowDeletes bool) error {
    if len(changes) == 0 {
        return nil
    }

    // Check for duplicates within changes, split in 'updates' and 'deletes' lists (sorted).
    updates, deletes, err := processChangesG(changes)
    if err != nil {
        return err
    }

    if !allowDeletes && len(deletes) != 0 {
        return fmt.Errorf("cannot process validators with voting power 0: %v", deletes)
    }

    // Check that the resulting set will not be empty.
    if numNewValidatorsG(updates, valg) == 0 && len(valg.Validators) == len(deletes) {
        return errors.New("applying the validator changes would result in empty set")
    }

    // Verify that applying the 'deletes' against 'valg' will not result in error.
    // Get the voting power that is going to be removed.
    removedVotingPower, err := verifyRemovalG(deletes, valg)
    if err != nil {
        return err
    }

    // Verify that applying the 'updates' against 'valg' will not result in error.
    // Get the updated total voting power before removal. Note that this is < 2 * MaxTotalVotingPower
    tvpAfterUpdatesBeforeRemovalg, err := verifyUpdatesG(updates, valg, removedVotingPower)
    if err != nil {
        return err
    }

    // Compute the priorities for updates.
    computeNewPrioritiesG(updates, valg, tvpAfterUpdatesBeforeRemovalg)

    // Apply updates and removalg.
    valg.applyUpdatesG(updates)
    valg.applyRemovalsG(deletes)

    valg.updateTotalVotingPower() // will panic if total voting power > MaxTotalVotingPower

    // Scale and center.
    valg.RescalePriorities(PriorityWindowSizeFactor * valg.TotalVotingPower())
    valg.shiftByAvgProposerPriority()

    sort.Sort(ValidatorsByVotingPowerG{Group: valg})

    return nil
}

// UpdateWithChangeGroup attempts to update the validator group with 'changes'.
// It performs the following steps:
//   - validates the changes making sure there are no duplicates and splits them in updates and deletes
//   - verifies that applying the changes will not result in errors
//   - computes the total voting power BEFORE removals to ensure that in the next steps the priorities
//     across old and newly added validators are fair
//   - computes the priorities of new validators against the final group
//   - applies the updates against the validator group
//   - applies the removals against the validator group
//   - performs scaling and centering of priority values
//
// If an error is detected during verification steps, it is returned and the validator group
// is not changed.
func (valg *ValidatorGroup) UpdateWithChangeGroup(changes []*Validator) error {
	return valg.updateWithChangeGroup(changes, true)
}

// findPreviousProposer reverses the compare proposer priority function to find the validator
// with the lowest proposer priority which would have been the previous proposer.
//
// Is used when recreating a validator group from an existing array of validators.
func (valg *ValidatorGroup) findPreviousProposer() *Validator {
	var previousProposer *Validator
	for _, val := range valg.Validators {
		if previousProposer == nil {
			previousProposer = val
			continue
		}
		if previousProposer == previousProposer.CompareProposerPriority(val) {
			previousProposer = val
		}
	}
	return previousProposer
}

// -----------------

// String returns a string representation of ValidatorGroup.
//
// See StringIndented.
func (valg *ValidatorGroup) String() string {
	return valg.StringIndented("")
}

// StringIndented returns an intended String.
//
// See Validator#String.
func (valg *ValidatorGroup) StringIndented(indent string) string {
	if valg == nil {
		return "nil-ValidatorGroup"
	}
	var valStrings []string
	valg.Iterate(func(_ int, val *Validator) bool {
		valStrings = append(valStrings, val.String())
		return false
	})
	return fmt.Sprintf(`ValidatorGroup{
%s  Proposer: %v
%s  Validators:
%s    %v
%s}`,
		indent, valg.GetProposer().String(),
		indent,
		indent, strings.Join(valStrings, "\n"+indent+"    "),
		indent)
}

// -------------------------------------

// ValidatorsByVotingPowerG implements sort.Interface for []*Validator based on
// the VotingPower and Address fields within a ValidatorGroup.
type ValidatorsByVotingPowerG struct {
    Group *ValidatorGroup
}

func (valg ValidatorsByVotingPowerG) Len() int { return len(valg.Group.Validators) }

func (valg ValidatorsByVotingPowerG) Less(i, j int) bool {
    if valg.Group.Validators[i].VotingPower == valg.Group.Validators[j].VotingPower {
        return bytes.Compare(valg.Group.Validators[i].Address, valg.Group.Validators[j].Address) == -1
    }
    return valg.Group.Validators[i].VotingPower > valg.Group.Validators[j].VotingPower
}

func (valg ValidatorsByVotingPowerG) Swap(i, j int) {
    valg.Group.Validators[i], valg.Group.Validators[j] = valg.Group.Validators[j], valg.Group.Validators[i]
}

// ValidatorsByAddressG implements sort.Interface for []*Validator based on
// the Address field within a ValidatorGroup.
type ValidatorsByAddressG struct {
	Group *ValidatorGroup
}

func (valz ValidatorsByAddressG) Len() int { return len(valz.Group.Validators) }

func (valz ValidatorsByAddressG) Less(i, j int) bool {
	return bytes.Compare(valz.Group.Validators[i].Address, valz.Group.Validators[j].Address) == -1
}

func (valz ValidatorsByAddressG) Swap(i, j int) {
	valz.Group.Validators[i], valz.Group.Validators[j] = valz.Group.Validators[j], valz.Group.Validators[i]
}

//TO-DO create ValidatorGroup proto
// ToProto converts ValidatorGroup to protobuf.
func (valg *ValidatorGroup) ToProto() (*cmtproto.ValidatorGroup, error) {
    if valg.IsNilOrEmpty() {
        return &cmtproto.ValidatorGroup{}, nil // validator group should never be nil
    }

    vp := new(cmtproto.ValidatorGroup)
    valgProto := make([]*cmtproto.Validator, len(valg.Validators))
    for i := 0; i < len(valg.Validators); i++ {
        valp, err := valg.Validators[i].ToProto()
        if err != nil {
            return nil, err
        }
        valgProto[i] = valp
    }
    vp.Validators = valgProto

    valProposer, err := valg.Proposer.ToProto()
    if err != nil {
        return nil, fmt.Errorf("toProto: validatorGroup proposer error: %w", err)
    }
    vp.Proposer = valProposer

    // NOTE: Sometimes we use the bytes of the proto form as a hash. This means that we need to
    // be consistent with cached data
    vp.TotalVotingPower = valg.totalVotingPower

    return vp, nil
}


// ValidatorGroupFromProto sets a protobuf ValidatorGroup to the given pointer.
// It returns an error if any of the validators from the group or the proposer
// is invalid.
func ValidatorGroupFromProto(vp *cmtproto.ValidatorGroup) (*ValidatorGroup, error) {
	if vp == nil {
		return nil, errors.New("nil validator group") // validator group should never be nil, bigger issues are at play if empty
	}
	valg := new(ValidatorGroup)

	valgProto := make([]*Validator, len(vp.Validators))
	for i := 0; i < len(vp.Validators); i++ {
		v, err := ValidatorFromProto(vp.Validators[i])
		if err != nil {
			return nil, err
		}
		valgProto[i] = v
	}
	valg.Validators = valgProto

	p, err := ValidatorFromProto(vp.GetProposer())
	if err != nil {
		return nil, fmt.Errorf("fromProto: validatorGroup proposer error: %w", err)
	}

	valg.Proposer = p

	// NOTE: We can't trust the total voting power given to us by other peers. If someone were to
	// inject a non-zeo value that wasn't the correct voting power we could assume a wrong total
	// power hence we need to recompute it.
	// FIXME: We should look to remove TotalVotingPower from proto or add it in the validators hash
	// so we don't have to do this
	valg.TotalVotingPower()

	return valg, valg.ValidateBasic()
}

// ValidatorGroupFromExistingValidators takes an existing array of validators and
// rebuilds the exact same validator group that corresponds to it without
// changing the proposer priority or power if any of the validators fail
// validate basic then an empty set is returned.
func ValidatorGroupFromExistingValidators(valz []*Validator) (*ValidatorGroup, error) {
	if len(valz) == 0 {
		return nil, errors.New("validator group is empty")
	}
	for _, val := range valz {
		err := val.ValidateBasic()
		if err != nil {
			return nil, fmt.Errorf("can't create validator group: %w", err)
		}
	}

	valg := &ValidatorGroup{
		Validators: valz,
	}
	valg.Proposer = valg.findPreviousProposer()
	valg.updateTotalVotingPower()
	sort.Sort(ValidatorsByVotingPowerG(valg.Validators))
	return valg, nil
}

// ----------------------------------------

// RandValidatorGroup returns a randomized validator group (size: +numValidators+),
// where each validator has a voting power of +votingPower+.
//
// EXPOSED FOR TESTING.
func RandValidatorGroup(numValidators int, votingPower int64) (*ValidatorGroup, []PrivValidator) {
	var (
		valz           = make([]*Validator, numValidators)
		privValidators = make([]PrivValidator, numValidators)
	)

	for i := 0; i < numValidators; i++ {
		val, privValidator := RandValidator(false, votingPower)
		valz[i] = val
		privValidators[i] = privValidator
	}

	sort.Sort(PrivValidatorsByAddress(privValidators))

	// TO-DO add groupID param
	return NewValidatorGroup(valz), privValidators
}



