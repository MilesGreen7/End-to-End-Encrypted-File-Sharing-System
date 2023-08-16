package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	//"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Password string
	SignKey userlib.DSSignKey
	RSAKey userlib.PKEDecKey
	MapsUUID userlib.UUID
	SymPKey []byte
	MACPKey []byte

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}
type UserMaps struct {
	OwnedFiles map[string]FilePtr
	SharedWithMe map[string]FilePtr
	FilesIShared map[string]map[string]FilePtr
}
type FilePtr struct {
	H userlib.UUID
	S []byte
	M []byte
}
type FileChunk struct {
	IsTail bool
	PrevChunkPtr FilePtr
	Content []byte
}

func StoreStruct(storeMarsh []byte, encKey []byte, macKey []byte, storeUUID userlib.UUID) (err error) {

	iv := userlib.RandomBytes(16)
	tCipher := userlib.SymEnc(encKey, iv, storeMarsh)
	tMAC, err := userlib.HMACEval(macKey, tCipher)
	if err != nil {
		return err
	}
	tBundle := append(tCipher, tMAC...)
	userlib.DatastoreSet(storeUUID, tBundle)

	return nil
}

func GetStruct(decKey []byte, macKey []byte, getUUID userlib.UUID) (marshStruct []byte, err error) {

	tBundle, ok := userlib.DatastoreGet(getUUID)
	if !ok {
		err = errors.New("GetStruct: Error getting data from DataStore")
		return nil, err
	}
	tHash := tBundle[(len(tBundle) - 64):len(tBundle)]
	tCipher := tBundle[0:(len(tBundle) - 64)]
	genHash, err := userlib.HMACEval(macKey, tCipher)
	if err != nil {
		return nil, err
	}
	equalMACs := userlib.HMACEqual(genHash, tHash)
	if !equalMACs {
		err = errors.New("GetStruct: Files have been tampered with")
		return nil, err
	}
	marshStruct = userlib.SymDec(decKey, tCipher)

	return marshStruct, nil
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" {
		err = errors.New("InitUser: Username is empty")
		return nil, err
	}
	userdata.Username = username
	userdata.Password = password
	hash := userlib.Hash([]byte(username))

	// this will be UUID of this user
	thisUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	_, ok := userlib.DatastoreGet(thisUUID)
	if ok {
		err = errors.New("InitUser: Username already exists")
		return nil, err
	}

	// Generating Digital signature keys; storing
	// private sign key in user struct and public
	// verify key in keystore
	tSign, tVerify, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.SignKey = tSign
	err = userlib.KeystoreSet(username + "-Verify", tVerify)
	if err != nil {
		return nil, err
	}

	// Generating RSA keys; storing private decryption
	// key in user struct, and public encryption key
	// in keystore
	tEnc, tDec, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	userdata.RSAKey = tDec
	err = userlib.KeystoreSet(username + "-Encrypt", tEnc)
	if err != nil {
		return nil, err
	}

	// generating random UUID for where hashmap
	// struct will be stored in datastore
	userdata.MapsUUID = uuid.New()

	// making hashmaps to store
	var myMaps UserMaps
	myMaps.OwnedFiles = make(map[string]FilePtr)
	myMaps.SharedWithMe = make(map[string]FilePtr)
	myMaps.FilesIShared = make(map[string]map[string]FilePtr)

	// generating random key for encryption and
	// generating random key for MAC
	userdata.SymPKey = userlib.RandomBytes(16)
	userdata.MACPKey = userlib.RandomBytes(16)

	// marshaling and storing maps
	mapMarsh, err := json.Marshal(&myMaps)
	if err != nil {
		return nil, err
	}
	err = StoreStruct(mapMarsh, userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return nil, err
	}

	// generating and storing new salt for storing user
	// data; stored under UUID "username" + "-salt"
	tSalt := userlib.RandomBytes(16)
	hash = userlib.Hash([]byte(username + "-salt"))
	saltUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	userlib.DatastoreSet(saltUUID, tSalt)

	// generating encrypt key for the userdata
	// using user's password
	userKey := userlib.Argon2Key([]byte(password), tSalt, 16)

	// marshalling and encrypting
	// don't need to store IV here
	tempMarsh, err := json.Marshal(&userdata)
	if err != nil {
		return nil, err
	}
	tSalt = userlib.RandomBytes(16)
	tCipher := userlib.SymEnc(userKey, tSalt, tempMarsh)

	// digitally signing user data and appending
	// signature to ciphertext
	tSignature, err := userlib.DSSign(tSign, tCipher)
	if err != nil {
		return nil, err
	}
	storedBundle := append(tCipher, tSignature...)

	//storing userdata in DataStore
	userlib.DatastoreSet(thisUUID, storedBundle)

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	if username == "" {
		err = errors.New("GetUser: Username is empty")
		return nil, err
	}

	// getting UUID of user and checking if they exist
	// in datastore
	hash := userlib.Hash([]byte(username))
	thisUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}
	storedBundle, ok := userlib.DatastoreGet(thisUUID)
	if !ok {
		err = errors.New("GetUser: User with this Username does not exist")
		return nil, err
	}

	// getting digital signature and ciphertext
	tSignature := storedBundle[(len(storedBundle) - 256):len(storedBundle)]
	tCipher := storedBundle[0:(len(storedBundle) - 256)]

	// verifying digital signature before decrypting

	// getting public verify key from keystore
	pSigKey, ok := userlib.KeystoreGet(username + "-Verify")
	if !ok {
		err = errors.New("GetUser: Error retrieving public key from KeyStore")
		return nil, err
	}

	// verify signature
	err = userlib.DSVerify(pSigKey, tCipher, tSignature)
	if err != nil {
		return nil, err
	}

	// generate user's symmetric key to decrypt ciphertext

	// generate UUID of salt to get it from datastore
	hash = userlib.Hash([]byte(username + "-salt"))
	saltUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		return nil, err
	}

	// get salt from datastore
	tSalt, ok := userlib.DatastoreGet(saltUUID)
	if !ok {
		err = errors.New("GetUser: Error retrieving salt from DataStore")
		return nil, err
	}

	// generate user's symmetric key using salt
	userKey := userlib.Argon2Key([]byte(password), tSalt, 16)

	// get marshalled user info by decrypting using key
	tempMarsh := userlib.SymDec(userKey, tCipher)

	// unmarshal data and return
	err = json.Unmarshal(tempMarsh, &userdata)
	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	// get the user's maps
	var myMaps UserMaps
	mapMarsh, err := GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return err
	}

	// booleans to decide what type of file it is
	oFilePtr, okO := myMaps.OwnedFiles[filename]
	swmFilePtr, okSWM := myMaps.SharedWithMe[filename]

	// we have three cases:
	// (1) the file already exists and is owned
	// (2) the file already exists and was shared with current user
	// (3) the file does not exist yet and must be created

	if okSWM {

		// file exists and was shared

		// get the Invite pointed to by swmFilePtr
		var invitePtr FilePtr
		fileMarsh, err := GetStruct(swmFilePtr.S, swmFilePtr.M, swmFilePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(fileMarsh, &invitePtr)
		if err != nil {
			return err
		}

		// get empty FileChunk pointed to by invitePtr
		var emptyChunk FileChunk
		emptyMarsh, err := GetStruct(invitePtr.S, invitePtr.M, invitePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(emptyMarsh, &emptyChunk)
		if err != nil {
			return err
		}

		// get FileChunk pointed to by emptyChunk
		var dataChunk FileChunk
		tPtr := emptyChunk.PrevChunkPtr
		chunkMarsh, err := GetStruct(tPtr.S, tPtr.M, tPtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(chunkMarsh, &dataChunk)
		if err != nil {
			return err
		}

		// set dataChunk fields
		if content == nil {
			dataChunk.Content = []byte("")
		} else {
			dataChunk.Content = content
		}

		// loop over chunks, deleting all of them from datastore
		var rChunk FileChunk
		delID := rChunk.PrevChunkPtr.H
		rChunk = dataChunk
		for {
			if rChunk.IsTail {
				break
			}
			fpMarsh, err := GetStruct(rChunk.PrevChunkPtr.S, rChunk.PrevChunkPtr.M, rChunk.PrevChunkPtr.H)
			if err != nil {
				return err
			}
			err = json.Unmarshal(fpMarsh, &rChunk)
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(delID)
			delID = rChunk.PrevChunkPtr.H
		}
		dataChunk.IsTail = true
		dataChunk.PrevChunkPtr.H = uuid.New()

		// store dataChunk
		dataMarsh, err := json.Marshal(&dataChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(dataMarsh, tPtr.S, tPtr.M, tPtr.H)
		if err != nil {
			return err
		}

		// store emptyChunk
		eMarsh, err := json.Marshal(&emptyChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(eMarsh, invitePtr.S, invitePtr.M, invitePtr.H)
		if err != nil {
			return err
		}

		// store invitePtr
		filePMarsh, err := json.Marshal(&invitePtr)
		if err != nil {
			return err
		}
		err = StoreStruct(filePMarsh, swmFilePtr.S, swmFilePtr.M, swmFilePtr.H)
		if err != nil {
			return err
		}

	} else if okO {

		// file does exist and is owned

		// get the FilePtr pointed to by oFilePtr
		var nxtFilePtr FilePtr
		fileMarsh, err := GetStruct(oFilePtr.S, oFilePtr.M, oFilePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(fileMarsh, &nxtFilePtr)
		if err != nil {
			return err
		}

		// get empty FileChunk pointed to by nxtFilePtr
		var emptyChunk FileChunk
		emptyMarsh, err := GetStruct(nxtFilePtr.S, nxtFilePtr.M, nxtFilePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(emptyMarsh, &emptyChunk)
		if err != nil {
			return err
		}

		// get FileChunk pointed to by emptyChunk
		var dataChunk FileChunk
		tPtr := emptyChunk.PrevChunkPtr
		chunkMarsh, err := GetStruct(tPtr.S, tPtr.M, tPtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(chunkMarsh, &dataChunk)
		if err != nil {
			return err
		}

		// set dataChunk fields
		if content == nil {
			dataChunk.Content = []byte("")
		} else {
			dataChunk.Content = content
		}

		// loop over chunks, deleting all of them from datastore
		var rChunk FileChunk
		delID := rChunk.PrevChunkPtr.H
		rChunk = dataChunk
		for {
			if rChunk.IsTail {
				break
			}
			fpMarsh, err := GetStruct(rChunk.PrevChunkPtr.S, rChunk.PrevChunkPtr.M, rChunk.PrevChunkPtr.H)
			if err != nil {
				return err
			}
			err = json.Unmarshal(fpMarsh, &rChunk)
			if err != nil {
				return err
			}
			userlib.DatastoreDelete(delID)
			delID = rChunk.PrevChunkPtr.H
		}
		dataChunk.IsTail = true
		dataChunk.PrevChunkPtr.H = uuid.New()

		// store dataChunk
		dataMarsh, err := json.Marshal(&dataChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(dataMarsh, tPtr.S, tPtr.M, tPtr.H)
		if err != nil {
			return err
		}

		// store emptyChunk
		eMarsh, err := json.Marshal(&emptyChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(eMarsh, nxtFilePtr.S, nxtFilePtr.M, nxtFilePtr.H)
		if err != nil {
			return err
		}

		// store nxtFilePtr
		filePMarsh, err := json.Marshal(&nxtFilePtr)
		if err != nil {
			return err
		}
		err = StoreStruct(filePMarsh, oFilePtr.S, oFilePtr.M, oFilePtr.H)
		if err != nil {
			return err
		}

	} else {

		// file does not exist yet

		// make new FilePtr and generate values for fields;
		// this is first FilePtr that's stored in map
		var mapFile FilePtr
		mapFile.H = uuid.New()               // newFile below stored under this uuid
		mapFile.S = userlib.RandomBytes(16)  // newFile below encrypted with this key
		mapFile.M = userlib.RandomBytes(16)  // newFile below MACed with this key
		myMaps.OwnedFiles[filename] = mapFile

		// make another FilePtr; this one is stored
		// in datastore and is pointed to by one above and
		// encrypted using keys of one above
		var newFile FilePtr
		newFile.H = uuid.New()                // where we store newChunk below
		newFile.S = userlib.RandomBytes(16)   // newChunk encrypted with this key
		newFile.M = userlib.RandomBytes(16)   // newChunk MACed with this key

		// make a new filechunk; this is stored in datastore
		// under uuid stored in FilePtr above and encrypted
		// using keys of FilePtr above
		var newChunk FileChunk
		newChunk.IsTail = true
		if content == nil {
			newChunk.Content = []byte("")
		} else {
			newChunk.Content = content
		}

		// make empty head chunk
		var emptyChunk FileChunk
		emptyChunk.IsTail = false
		emptyChunk.Content = []byte("")
		emptyChunk.PrevChunkPtr.H = uuid.New()               // UUID of newChunk
		emptyChunk.PrevChunkPtr.S = userlib.RandomBytes(16)  // encrypt key of newChunk
		emptyChunk.PrevChunkPtr.M = userlib.RandomBytes(16)  // MAC key of newChunk

		// marshal and store newChunk using keys and UUID of emptyChunk
		chunkMarsh, err := json.Marshal(&newChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(chunkMarsh, emptyChunk.PrevChunkPtr.S, emptyChunk.PrevChunkPtr.M, emptyChunk.PrevChunkPtr.H)
		if err != nil {
			return err
		}

		// marshal and store emptyChunk using keys and UUID of newFile
		emptyMarsh, err := json.Marshal(&emptyChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(emptyMarsh, newFile.S, newFile.M, newFile.H)
		if err != nil {
			return err
		}

		// marshal and store newFile
		fileMarsh, err := json.Marshal(&newFile)
		if err != nil {
			return err
		}
		err = StoreStruct(fileMarsh, mapFile.S, mapFile.M, mapFile.H)
		if err != nil {
			return err
		}
	}

	// store the user's maps
	mapTMarsh, err := json.Marshal(&myMaps)
	if err != nil {
		return err
	}
	err = StoreStruct(mapTMarsh, userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	// get the user's maps
	var myMaps UserMaps
	mapMarsh, err := GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return err
	}

	// booleans to decide what type of file it is
	oFilePtr, okO := myMaps.OwnedFiles[filename]
	swmFilePtr, okSWM := myMaps.SharedWithMe[filename]

	// three cases:
	// (1) file is shared with the user and not owned
	// (2) file is owned by the user
	// (3) file is neither in which case it doesn't exist and we return error

	if okSWM {

		//file is shared with user

		// get the Invite pointed to by swmFilePtr
		var invitePtr FilePtr
		fileMarsh, err := GetStruct(swmFilePtr.S, swmFilePtr.M, swmFilePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(fileMarsh, &invitePtr)
		if err != nil {
			return err
		}

		// get FileChunk pointed to by invitePtr
		var emptyChunk FileChunk
		chunkMarsh, err := GetStruct(invitePtr.S, invitePtr.M, invitePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(chunkMarsh, &emptyChunk)
		if err != nil {
			return err
		}

		// create new FileChunk
		var newChunk FileChunk
		newChunk.IsTail = false
		if content == nil {
			newChunk.Content = []byte("")
		} else {
			newChunk.Content = content
		}

		// assign emptyChunk keys and UUID to newChunk
		newChunk.PrevChunkPtr.H = emptyChunk.PrevChunkPtr.H
		newChunk.PrevChunkPtr.S = emptyChunk.PrevChunkPtr.S
		newChunk.PrevChunkPtr.M = emptyChunk.PrevChunkPtr.M

		// assign new keys and UUID to emptyChunk
		emptyChunk.PrevChunkPtr.H = uuid.New()          // UUID for newChunk
		emptyChunk.PrevChunkPtr.S = userlib.RandomBytes(16)  // encryption key for newChunk
		emptyChunk.PrevChunkPtr.M = userlib.RandomBytes(16)  // MAC key for newChunk

		// store newChunk
		nMarsh, err := json.Marshal(&newChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(nMarsh, emptyChunk.PrevChunkPtr.S, emptyChunk.PrevChunkPtr.M, emptyChunk.PrevChunkPtr.H)
		if err != nil {
			return err
		}

		// store emptyChunk using invitePtr keys and UUID
		newMarsh, err := json.Marshal(&emptyChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(newMarsh, invitePtr.S, invitePtr.M, invitePtr.H)
		if err != nil {
			return err
		}

		// rest of data doesn't have to be stored again (unchanged)????

	} else if okO {

		//file is owned by user

		// get the FilePtr pointed to by oFilePtr
		var nxtFilePtr FilePtr
		fileMarsh, err := GetStruct(oFilePtr.S, oFilePtr.M, oFilePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(fileMarsh, &nxtFilePtr)
		if err != nil {
			return err
		}

		// get emptyChunk pointed to by invitePtr
		var emptyChunk FileChunk
		chunkMarsh, err := GetStruct(nxtFilePtr.S, nxtFilePtr.M, nxtFilePtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(chunkMarsh, &emptyChunk)
		if err != nil {
			return err
		}

		// create new FileChunk
		var newChunk FileChunk
		newChunk.IsTail = false
		if content == nil {
			newChunk.Content = []byte("")
		} else {
			newChunk.Content = content
		}

		// assign emptyChunk keys and UUID to newChunk
		newChunk.PrevChunkPtr.H = emptyChunk.PrevChunkPtr.H
		newChunk.PrevChunkPtr.S = emptyChunk.PrevChunkPtr.S
		newChunk.PrevChunkPtr.M = emptyChunk.PrevChunkPtr.M

		// assign new keys and UUID to emptyChunk
		emptyChunk.PrevChunkPtr.H = uuid.New()          // UUID for newChunk
		emptyChunk.PrevChunkPtr.S = userlib.RandomBytes(16)  // encryption key for newChunk
		emptyChunk.PrevChunkPtr.M = userlib.RandomBytes(16)  // MAC key for newChunk

		// store newChunk
		nMarsh, err := json.Marshal(&newChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(nMarsh, emptyChunk.PrevChunkPtr.S, emptyChunk.PrevChunkPtr.M, emptyChunk.PrevChunkPtr.H)
		if err != nil {
			return err
		}

		// store emptyChunk using nxtFilePtr keys and UUID
		newMarsh, err := json.Marshal(&emptyChunk)
		if err != nil {
			return err
		}
		err = StoreStruct(newMarsh, nxtFilePtr.S, nxtFilePtr.M, nxtFilePtr.H)
		if err != nil {
			return err
		}

		// rest of data doesn't have to be stored again (unchanged)????

	} else {
		err = errors.New("AppendToFile: The filename passed does not exist in user's file space")
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	
	// get the user's maps
	var myMaps UserMaps
	mapMarsh, err := GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return nil, err
	}

	// booleans to decide what type of file it is
	oFilePtr, okO := myMaps.OwnedFiles[filename]
	swmFilePtr, okSWM := myMaps.SharedWithMe[filename]

	// three cases:
	// (1) file is shared with the user and not owned
	// (2) file is owned by the user
	// (3) file is neither in which case it doesn't exist and we return error

	if okSWM {

		//file is shared with user

		// get the Invite pointed to by swmFilePtr
		var invitePtr FilePtr
		fileMarsh, err := GetStruct(swmFilePtr.S, swmFilePtr.M, swmFilePtr.H)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(fileMarsh, &invitePtr)
		if err != nil {
			return nil, err
		}

		// get FileChunk pointed to by invitePtr
		var dataChunk FileChunk
		chunkMarsh, err := GetStruct(invitePtr.S, invitePtr.M, invitePtr.H)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(chunkMarsh, &dataChunk)
		if err != nil {
			return nil, err
		}

		if dataChunk.Content == nil {
			content = []byte("")
		} else {
			content = dataChunk.Content
		}

		// loop until we hit the last chunk (tail), reconstructing
		// content along the way

		var newContent []byte
		if !dataChunk.IsTail {
			for {

				// get next datachunk
				tPtr := dataChunk.PrevChunkPtr
				newChunkMarsh, err := GetStruct(tPtr.S, tPtr.M, tPtr.H)
				if err != nil {
					return nil, err
				}
				err = json.Unmarshal(newChunkMarsh, &dataChunk)
				if err != nil {
					return nil, err
				}

				// appending content
				newContent = dataChunk.Content
				if newContent == nil {
					newContent = []byte("")
				}
				content = append(newContent, content...)

				if dataChunk.IsTail {
					break
				}
			}
		}

	} else if okO {

		// file does exist and is owned

		// get the FilePtr pointed to by oFilePtr
		var nxtFilePtr FilePtr
		fileMarsh, err := GetStruct(oFilePtr.S, oFilePtr.M, oFilePtr.H)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(fileMarsh, &nxtFilePtr)
		if err != nil {
			return nil, err
		}

		// get FileChunk pointed to by nxtFilePtr
		var dataChunk FileChunk
		chunkMarsh, err := GetStruct(nxtFilePtr.S, nxtFilePtr.M, nxtFilePtr.H)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(chunkMarsh, &dataChunk)
		if err != nil {
			return nil, err
		}

		if dataChunk.Content == nil {
			content = []byte("")
		} else {
			content = dataChunk.Content
		}

		// loop until we hit the last chunk (tail), reconstructing
		// content along the way

		var newContent []byte
		if !dataChunk.IsTail {

			for {

				// get next datachunk
				tPtr := dataChunk.PrevChunkPtr
				newChunkMarsh, err := GetStruct(tPtr.S, tPtr.M, tPtr.H)
				if err != nil {
					return nil, err
				}
				err = json.Unmarshal(newChunkMarsh, &dataChunk)
				if err != nil {
					return nil, err
				}

				// appending content
				newContent = dataChunk.Content
				if newContent == nil {
					newContent = []byte("")
				}
				content = append(newContent, content...)

				if dataChunk.IsTail {
					break
				}
			}

		}

	} else {
		err = errors.New("LoadFile: The filename passed does not exist in user's file space")
		return nil, err
	}

	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	// check if recipient exists by checking if they have
	// public key in keystore
	_, ok := userlib.KeystoreGet(recipientUsername + "-Verify")
	if !ok {
		err = errors.New("CreateInvitation: Recipient user does not exist")
		return uuid.New(), err
	}

	// get user's maps
	var myMaps UserMaps
	mapMarsh, err := GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return uuid.New(), err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return uuid.New(), err
	}

	// booleans to decide what type of file it is
	oFilePtr, okO := myMaps.OwnedFiles[filename]
	swmFilePtr, okSWM := myMaps.SharedWithMe[filename]

	// where we store the UUID to return to recipient
	var returnUUID userlib.UUID

	// we have three cases:
	// (1) user is sharing a file that was shared with them (they're not the owner)
	// (2) user owns the file they're sharing
	// (3) user does not have access to filename passed or the file does not exist

	if okSWM {

		// user is sharing a file that was shared with them

		// create newFilePtr and copy contents of swmFilePtr into it
		var newFilePtr FilePtr
		newFilePtr.H = swmFilePtr.H
		newFilePtr.S = swmFilePtr.S
		newFilePtr.M = swmFilePtr.M

		// marshal newFilePtr
		newMarsh, err := json.Marshal(&newFilePtr)
		if err != nil {
			return uuid.New(), err
		}

		// get recipient's public RSA key
		recipRSA, ok := userlib.KeystoreGet(recipientUsername + "-Encrypt")
		if !ok {
			err = errors.New("CreateInvitation: Recipient user does not exist")
			return uuid.New(), err
		}

		// encrypt marshaled invite using recipient's public RSA key
		iCipher, err := userlib.PKEEnc(recipRSA, newMarsh)
		if err != nil {
			return uuid.New(), err
		}

		// sign using this user's private sign key
		iSignature, err := userlib.DSSign(userdata.SignKey, iCipher)
		if err != nil {
			return uuid.New(), err
		}

		// attach signature to ciphertext
		iBundle := append(iCipher, iSignature...)

		// store encrypted invitation
		returnUUID = uuid.New()
		userlib.DatastoreSet(returnUUID, iBundle)

	} else if okO {

		// user owns the file they're sharing

		// we need the FileChunk data stored in the pointer in user's maps
		// so we get the FilePtr pointed to by oFilePtr
		var nxtFilePtr FilePtr
		fileMarsh, err := GetStruct(oFilePtr.S, oFilePtr.M, oFilePtr.H)
		if err != nil {
			return uuid.New(), err
		}
		err = json.Unmarshal(fileMarsh, &nxtFilePtr)
		if err != nil {
			return uuid.New(), err
		}

		// create invite and copy pointer info
		var invitation FilePtr
		invitation.H = nxtFilePtr.H
		invitation.S = nxtFilePtr.S
		invitation.M = nxtFilePtr.M

		// now create newFilePtr and gen new data
		var newFilePtr FilePtr
		newFilePtr.H = uuid.New()               // store invite here
		newFilePtr.S = userlib.RandomBytes(16)  // encrypt invite with this key
		newFilePtr.M = userlib.RandomBytes(16)  // MAC invite with this key

		// return error if the file has already been shared with this recipient
		_, ok := myMaps.FilesIShared[filename][recipientUsername]
		if ok {
			err = errors.New("CreateInvitation: File has already been shared with this recipient")
			return uuid.New(), err
		}

		// store newFilePtr in this user's FilesIShared map under [filename][recipientUsername]
		_, ok = myMaps.FilesIShared[filename]
		if !ok {
			myMaps.FilesIShared[filename] = make(map[string]FilePtr)
		}
		myMaps.FilesIShared[filename][recipientUsername] = newFilePtr

		// store invite in datastore using newFilePtr keys and UUID
		inviteMarsh, err := json.Marshal(&invitation)
		if err != nil {
			return uuid.New(), err
		}
		err = StoreStruct(inviteMarsh, newFilePtr.S, newFilePtr.M, newFilePtr.H)
		if err != nil {
			return uuid.New(), err
		}

		// marshal newFilePtr
		newMarsh, err := json.Marshal(&newFilePtr)
		if err != nil {
			return uuid.New(), err
		}

		// get recipient's public RSA key
		recipRSA, ok := userlib.KeystoreGet(recipientUsername + "-Encrypt")
		if !ok {
			err = errors.New("CreateInvitation: Recipient user does not exist")
			return uuid.New(), err
		}

		// encrypt marshaled newFilePtr using recipient's public RSA key
		iCipher, err := userlib.PKEEnc(recipRSA, newMarsh)
		if err != nil {
			return uuid.New(), err
		}

		// sign using this user's private sign key
		iSignature, err := userlib.DSSign(userdata.SignKey, iCipher)
		if err != nil {
			return uuid.New(), err
		}

		// attach signature to ciphertext
		iBundle := append(iCipher, iSignature...)

		// store encrypted invitation
		returnUUID = uuid.New()
		userlib.DatastoreSet(returnUUID, iBundle)

		// store the user's maps
		mapTMarsh, err := json.Marshal(&myMaps)
		if err != nil {
			return uuid.New(), err
		}
		err = StoreStruct(mapTMarsh, userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
		if err != nil {
			return uuid.New(), err
		}

	} else {

		err = errors.New("CreateInvitation: File does not exist in user's filespace")
		return uuid.New(), err
	}

	return returnUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {

	// for all cases we verify with public key and decrypt with private key

	// check if sender exists
	_, ok := userlib.KeystoreGet(senderUsername + "-Encrypt")
	if !ok {
		err := errors.New("AcceptInvitation: Sender does not exist")
		return err
	}

	// get user's maps
	var myMaps UserMaps
	mapMarsh, err := GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return err
	}

	// booleans to determine if filename is in namespace of this user
	_, okO := myMaps.OwnedFiles[filename]
	_, okSWM := myMaps.SharedWithMe[filename]
	if ( okO || okSWM ) {
		err = errors.New("AcceptInvitation: Filename already exists in user's filespace")
		return err
	}

	// get sent data bundle from datastore
	bundlePtr, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		err = errors.New("AcceptInvitation: Error getting data from DataStore")
		return err
	}

	// get signature and encrypted data from bundle
	tSignature := bundlePtr[(len(bundlePtr) - 256):len(bundlePtr)]
	tCipher := bundlePtr[0:(len(bundlePtr) - 256)]

	// get public key of sender
	tVerify, ok := userlib.KeystoreGet(senderUsername + "-Verify")
	if !ok {
		err = errors.New("AcceptInvitation: Sender does not exist")
		return err
	}

	// verify signature
	err = userlib.DSVerify(tVerify, tCipher, tSignature)
	if err != nil {
		return err
	}

	// decrypt data
	marshPtr, err := userlib.PKEDec(userdata.RSAKey, tCipher)
	if err != nil {
		return err
	}

	// unmarshal data
	var sharedPtr FilePtr
	err = json.Unmarshal(marshPtr, &sharedPtr)
	if err != nil {
		return err
	}

	// check if FilePtr under the UUID in sharedPtr exists
	_, ok = userlib.DatastoreGet(sharedPtr.H)
	if !ok {
		err = errors.New("AcceptInvitation: Invitation no longer valid due to revocation")
		return err
	}

	// store sharedPtr in user's maps
	myMaps.SharedWithMe[filename] = sharedPtr

	// delete sent FilePtr from DataStore
	userlib.DatastoreDelete(invitationPtr)

	// store the user's maps
	mapTMarsh, err := json.Marshal(&myMaps)
	if err != nil {
		return err
	}
	err = StoreStruct(mapTMarsh, userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	// makes sure all files shared with revoked user are deleted (invites, and files containing content)

	// delete their invitation in datastore but can leave their fileptr if they haven't excepted invite yet

	// get user's maps
	var myMaps UserMaps
	mapMarsh, err := GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return err
	}

	// get filePtr from ownedFiles
	oFilePtr, okO := myMaps.OwnedFiles[filename]
	if !okO {
		err = errors.New("RevokeAccess: File does not exist in user's filespace")
		return err
	}

	// check if filename-recipientUsername is in FilesIShared map
	fisPtr, okFIS := myMaps.FilesIShared[filename][recipientUsername]
	if !okFIS {
		err = errors.New("RevokeAccess: File has not been shared with this user")
		return err
	}

	// store UUID to delete from datastore later
	deleteH := fisPtr.H

	// get nxtFilePtr
	var nxtFilePtr FilePtr
	fileMarsh, err := GetStruct(fisPtr.S, fisPtr.M, fisPtr.H)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileMarsh, &nxtFilePtr)
	if err != nil {
		return err
	}

	// setup variables for iterating over FileChunks
	prevChunkID := nxtFilePtr.H
	content := []byte("")

	// get nextChunk
	var nextChunk FileChunk
	chunkMarsh, err := GetStruct(nxtFilePtr.S, nxtFilePtr.M, nxtFilePtr.H)
	if err != nil {
		return err
	}
	err = json.Unmarshal(chunkMarsh, &nextChunk)
	if err != nil {
		return err
	}

	// loop over chunks, appending content and deleting each chunk from Datastore
	for {
		// save the content in the chunk
		content = append(nextChunk.Content, content...)

	 	// delete previous chunk and save the new prevChunkID
	 	userlib.DatastoreDelete(prevChunkID)

	 	// if this is tail chunk, end loop
	 	if nextChunk.IsTail {
	 		break
	 	}
	 	prevChunkID = nextChunk.PrevChunkPtr.H

	 	// get the new nextChunk
	 	chunkMarsh, err = GetStruct(nextChunk.PrevChunkPtr.S, nextChunk.PrevChunkPtr.M, nextChunk.PrevChunkPtr.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(chunkMarsh, &nextChunk)
		if err != nil {
			return err
		}
	}

	// delete invite in datastore using saved UUID
	userlib.DatastoreDelete(deleteH)

	// remove user from FilesIShared map
	delete(myMaps.FilesIShared[filename], recipientUsername)

	// delete owner's fileptr that's in datastore
	userlib.DatastoreDelete(oFilePtr.H)

	// remove entry in ownedMaps
	delete(myMaps.OwnedFiles, filename)

	// store the user's maps
	mapTMarsh, err := json.Marshal(&myMaps)
	if err != nil {
		return err
	}
	err = StoreStruct(mapTMarsh, userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}

	// restore the file in ownedfiles
	userdata.StoreFile(filename, content)

	// get user's maps
	mapMarsh, err = GetStruct(userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}
	err = json.Unmarshal(mapMarsh, &myMaps)
	if err != nil {
		return err
	}

	// get new ownedFilePtr
	oFilePtr, okO = myMaps.OwnedFiles[filename]
	if !okO {
		err = errors.New("RevokeAccess: File does not exist in user's filespace")
		return err
	}

	// get nxtFilePtr
	fileMarsh, err = GetStruct(oFilePtr.S, oFilePtr.M, oFilePtr.H)
	if err != nil {
		return err
	}
	err = json.Unmarshal(fileMarsh, &nxtFilePtr)
	if err != nil {
		return err
	}

	// update the invites for the users the file was shared with
	for _, v := range myMaps.FilesIShared[filename] {

		// get invite
		var invStruct FilePtr
		iMarsh, err := GetStruct(v.S, v.M, v.H)
		if err != nil {
			return err
		}
		err = json.Unmarshal(iMarsh, &invStruct)
		if err != nil {
			return err
		}

		// save location and keys of newChunk in invite
		invStruct.H = nxtFilePtr.H
		invStruct.S = nxtFilePtr.S
		invStruct.M = nxtFilePtr.M

		// store modified invite back in datastore
		filePMarsh, err := json.Marshal(&invStruct)
		if err != nil {
			return err
		}
		err = StoreStruct(filePMarsh, v.S, v.M, v.H)
		if err != nil {
			return err
		}
	}

	// store the user's maps
	mapTMarsh, err = json.Marshal(&myMaps)
	if err != nil {
		return err
	}
	err = StoreStruct(mapTMarsh, userdata.SymPKey, userdata.MACPKey, userdata.MapsUUID)
	if err != nil {
		return err
	}

	return nil
}
