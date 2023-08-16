package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var temp *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})
	Describe("My Tests", func() {

		Specify("My Test: Testing if users can login with incorrect password.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice with incorrect password")
			aliceLaptop, err = client.GetUser("alice", "hello")
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Testing if users can create account eith empty username.", func() {
			userlib.DebugMsg("Initializing user.")
			aliceDesktop, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Testing if users can have same usernames.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			bob, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Creating user with empty password.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			aliceDesktop, err = client.InitUser("alice", "")
			Expect(err).To(BeNil())

			userlib.DebugMsg("My Test: Testing that user can be retrieved with empty password")
			aliceLaptop, err = client.GetUser("alice", "")
			Expect(err).To(BeNil())
		})
		Specify("My Test: Testing that bob and Bob are different users", func() {
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user bob.")
			temp, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing Bob's File")
			err = bob.StoreFile("hey", []byte("how are you"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Trying to load bob's file (error expected)")
			_, err = temp.LoadFile("hey")
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Testing empty filename", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello")
			err = alice.StoreFile("", []byte("hello"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading Data")
			data, err := alice.LoadFile("")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hello")))
		})
		Specify("My Test: Checking that user's filespaces are independent", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello")
			err = alice.StoreFile("safe.txt", []byte("hello"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "there")
			err = bob.StoreFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading Data")
			data, err := alice.LoadFile("safe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hello")))

			userlib.DebugMsg("Loading Data")
			data, err = bob.LoadFile("safe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("there")))
		})
		Specify("My Test: Testing revocation when file invite is not accepted", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello world!")
			err = alice.StoreFile("safe.txt", []byte("hello world!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Claire.")
			claire, err := client.InitUser("Claire", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob")
			invite, err := alice.CreateInvitation("safe.txt", "Bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Claire")
			invite2, err := alice.CreateInvitation("safe.txt", "Claire")
			Expect(err).To(BeNil())

			err = claire.AcceptInvitation("Alice", invite2, "notsafe.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from safe.txt")
			err = alice.RevokeAccess("safe.txt", "Bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if Bob can accept invite")
			err = bob.AcceptInvitation("Alice", invite, "notsafe.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking if Claire can still load data")
			data, err := claire.LoadFile("notsafe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hello world!")))
		})
		Specify("My Test: Testing revoke user where two users have not accepted invite and one is revoked", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello world!")
			err = alice.StoreFile("safe.txt", []byte("hello world!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Claire.")
			claire, err := client.InitUser("Claire", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob")
			invite, err := alice.CreateInvitation("safe.txt", "Bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Claire")
			invite2, err := alice.CreateInvitation("safe.txt", "Claire")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access from safe.txt")
			err = alice.RevokeAccess("safe.txt", "Bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if Bob can accept invite")
			err = bob.AcceptInvitation("Alice", invite, "notsafe.txt")
			Expect(err).ToNot(BeNil())

			err = claire.AcceptInvitation("Alice", invite2, "notsafe.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking if Claire can still load data")
			data, err := claire.LoadFile("notsafe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hello world!")))
			
		})
		Specify("My Test: Testing sharing a file where there's name conflicts with shared file", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello world!")
			err = alice.StoreFile("safe.txt", []byte("hello world!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("Bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hey")
			err = bob.StoreFile("notsafe.txt", []byte("hey"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Bob")
			invite, err := alice.CreateInvitation("safe.txt", "Bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts invite")
			err = bob.AcceptInvitation("Alice", invite, "notsafe.txt")
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Testing storing a file where there's name conflicts with storing the file", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello world!")
			err = alice.StoreFile("safe.txt", []byte("hello world!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hey")
			err = alice.StoreFile("safe.txt", []byte("hey"))
			Expect(err).To(BeNil())
		})
		Specify("My test: Testing overwrite of appended file and revoke of appended file.", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello world!")
			err = alice.StoreFile("safe.txt", []byte("hello world!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Claire.")
			claire, err := client.InitUser("Claire", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Claire")
			invite2, err := alice.CreateInvitation("safe.txt", "Claire")
			Expect(err).To(BeNil())

			err = claire.AcceptInvitation("Alice", invite2, "notsafe.txt")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Claire appending to file")
			err = claire.AppendToFile("notsafe.txt", []byte("hey"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Claire loading data")
			data, err := claire.LoadFile("notsafe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hello world!therehey")))

			userlib.DebugMsg("Alice overwriting safe.txt")
			err = alice.StoreFile("safe.txt", []byte("hi there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Claire appending to file")
			err = claire.AppendToFile("notsafe.txt", []byte(" you"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Claire loading data")
			data, err = claire.LoadFile("notsafe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hi there youtheretherethere")))

			userlib.DebugMsg("Claire overwriting file")
			err = claire.StoreFile("notsafe.txt", []byte("hello"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loading data")
			data, err = alice.LoadFile("safe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hello")))

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Claire appending to file")
			err = claire.AppendToFile("notsafe.txt", []byte("there"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking David's access from safe.txt")
			err = alice.RevokeAccess("safe.txt", "David")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking David's access from dare.txt")
			err = alice.RevokeAccess("dare.txt", "Claire")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Claire revoking Alice's access from dare.txt")
			err = claire.RevokeAccess("notsafe.txt", "Alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice revoking Claire's access from safe.txt")
			err = alice.RevokeAccess("safe.txt", "Claire")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking David's access from safe.txt")
			err = alice.RevokeAccess("safe.txt", "David")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice loading data")
			data, err = alice.LoadFile("safe.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hellotheretherethere")))

			userlib.DebugMsg("Checking if Claire can still load data")
			data, err = claire.LoadFile("notsafe.txt")
			Expect(err).ToNot(BeNil())		
		})
		Specify("My Test: Testing conflicting usernames", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			aliceDesktop, err = client.InitUser("Alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Testing loading of a user that doesn't exist", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())

		})
		Specify("My test: Loading and appending file that doesn't exist", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice loading data")
			_, err := alice.LoadFile("notsafe.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appending to file")
			err = alice.AppendToFile("safe.txt", []byte("there"))
			Expect(err).ToNot(BeNil())
		})
		Specify("My Test: Testing creating invite where recipient does not exist", func() {

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("Alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hello world!")
			err = alice.StoreFile("safe.txt", []byte("hello world!"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", "hey")
			err = alice.StoreFile("safe.txt", []byte("hey"))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Claire")
			invite2, err := alice.CreateInvitation("safe.txt", "Claire")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Initializing user Claire.")
			claire, err := client.InitUser("Claire", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creates invite for Claire")
			invite2, err = alice.CreateInvitation("notsafe.txt", "Claire")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creates invite for Claire")
			invite2, err = alice.CreateInvitation("safe.txt", "Claire")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Claire accepts invite")
			err = claire.AcceptInvitation("David", invite2, "notsafe.txt")
			Expect(err).ToNot(BeNil())
		})
	})
})
