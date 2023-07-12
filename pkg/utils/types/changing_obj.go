package types

import (
	"sync"
)

// Timestamp is a regulation of time types
type Timestamp int

// State represent a change of value - the new value and the time of the change
type State[T any] struct {
	StartTime Timestamp
	Val       T
}

// ChangingObj represents a value that changes over time.
// It exposes the value at a given time, assuming that between two changes the value is constant.
// The object is designed to be thread-safe.
type ChangingObj[T any] struct {
	states []State[T]
	mu     sync.RWMutex
}

func NewChangingObj[T any](defaultVal T) *ChangingObj[T] {
	defaultState := State[T]{
		StartTime: 0,
		Val:       defaultVal,
	}
	return &ChangingObj[T]{
		states: []State[T]{defaultState},
	}
}

// AddState add a change in the value - from given time until next change, the value is the new one.
func (co *ChangingObj[T]) AddState(newState State[T]) {
	co.mu.Lock()
	defer co.mu.Unlock()
	insertIndex := co.getRelevantStateIndex(newState.StartTime) + 1
	stateList := make([]State[T], len(co.states)+1)
	copy(stateList[:insertIndex], co.states[:insertIndex])
	copy(stateList[insertIndex+1:], co.states[insertIndex:])
	stateList[insertIndex] = newState
	co.states = stateList
}

// Get return the value at a given time
func (co *ChangingObj[T]) Get(time Timestamp) T {
	relevantState := co.GetState(time)
	return relevantState.Val
}

// GetState return the value at a given time, and the time it was changed to this value
func (co *ChangingObj[T]) GetState(time Timestamp) State[T] {
	co.mu.RLock()
	defer co.mu.RUnlock()
	relevantStateIndex := co.getRelevantStateIndex(time)
	return co.states[relevantStateIndex]
}

// ChangeDefault change the value assumed before first recorded change
func (co *ChangingObj[T]) ChangeDefault(defaultVal T) {
	co.mu.Lock()
	defer co.mu.Unlock()
	co.states[0].Val = defaultVal
}

func (co *ChangingObj[T]) getRelevantStateIndex(time Timestamp) int {
	low := 0
	high := len(co.states) - 1
	closestIndex := 0

	for low <= high {
		mid := low + (high-low)/2

		if co.states[mid].StartTime <= time {
			closestIndex = mid
			low = mid + 1 // Target is in the right half
		} else {
			high = mid - 1 // Target is in the left half
		}
	}
	return closestIndex
}
