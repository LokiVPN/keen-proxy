package engine

import (
	"container/list"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	subscriptionBalanceSessionLimit = 1024
	subscriptionBalanceSessionIdle  = 30 * time.Minute
)

// subscriptionBalanceSessions belongs to one applied source identity. It keeps
// tags rather than outbound instances so an engine restart can restore affinity.
type subscriptionBalanceSessions struct {
	sourceKey string
	mu        sync.Mutex
	recent    list.List
	entries   map[subscriptionBalanceSessionKey]*list.Element
}

type subscriptionBalanceSessionKey struct {
	client netip.Addr
	site   string
}

type subscriptionBalanceSession struct {
	key      subscriptionBalanceSessionKey
	primary  string
	fallback string
	lastUsed time.Time
}

// snapshot preserves the LRU order and pre-Apply affinities for rollback.
func (s *subscriptionBalanceSessions) snapshot() *subscriptionBalanceSessions {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := &subscriptionBalanceSessions{sourceKey: s.sourceKey}
	if len(s.entries) != 0 {
		copy.entries = make(map[subscriptionBalanceSessionKey]*list.Element, len(s.entries))
	}
	for element := s.recent.Front(); element != nil; element = element.Next() {
		entry := *element.Value.(*subscriptionBalanceSession)
		copy.entries[entry.key] = copy.recent.PushBack(&entry)
	}
	return copy
}

func (s *subscriptionBalanceSessions) selectMember(key subscriptionBalanceSessionKey, members, alternate []subscriptionBalanceMember) adapter.Outbound {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selectAt(key, members, alternate, time.Now(), rand.IntN)
}

func (s *subscriptionBalanceSessions) selectAt(key subscriptionBalanceSessionKey, members, alternate []subscriptionBalanceMember, now time.Time, randomIndex func(int) int) adapter.Outbound {
	for oldest := s.recent.Back(); oldest != nil; oldest = s.recent.Back() {
		if now.Sub(oldest.Value.(*subscriptionBalanceSession).lastUsed) < subscriptionBalanceSessionIdle {
			break
		}
		s.remove(oldest)
	}
	entry := s.entries[key]
	if entry == nil {
		if len(s.entries) == subscriptionBalanceSessionLimit {
			s.remove(s.recent.Back())
		}
		if s.entries == nil {
			s.entries = make(map[subscriptionBalanceSessionKey]*list.Element)
		}
		entry = s.recent.PushFront(&subscriptionBalanceSession{key: key})
		s.entries[key] = entry
	}
	session := entry.Value.(*subscriptionBalanceSession)
	session.lastUsed = now
	s.recent.MoveToFront(entry)
	return session.selectMember(members, alternate, randomIndex)
}

// selectMember keeps a healthy primary when the other transport needs a
// fallback. The fallback has its own affinity within the same cache entry.
func (s *subscriptionBalanceSession) selectMember(members, alternate []subscriptionBalanceMember, randomIndex func(int) int) adapter.Outbound {
	if primary := subscriptionBalanceMemberByTag(members, s.primary); primary != nil {
		return primary
	}
	member := subscriptionBalanceMemberByTag(members, s.fallback)
	if member == nil {
		member = members[randomIndex(len(members))].outbound
	}
	if subscriptionBalanceMemberByTag(alternate, s.primary) != nil {
		s.fallback = member.Tag()
	} else {
		s.primary = member.Tag()
		if s.fallback == s.primary {
			s.fallback = ""
		}
	}
	return member
}

func subscriptionBalanceMemberByTag(members []subscriptionBalanceMember, tag string) adapter.Outbound {
	if tag == "" {
		return nil
	}
	for _, member := range members {
		if member.outbound.Tag() == tag {
			return member.outbound
		}
	}
	return nil
}

func (s *subscriptionBalanceSessions) remove(entry *list.Element) {
	delete(s.entries, entry.Value.(*subscriptionBalanceSession).key)
	s.recent.Remove(entry)
}
