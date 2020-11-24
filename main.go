// @authors: Alex Le-Tu, Jeffrey Weiner
// NO ADDED IMPORTS
import (
	"encoding/json"
	"encoding/hex"
	"github.com/google/uuid"
	"strings"
	"errors"
	_ "strconv"
)

// Constants all in one place 
const (
	AESKEYSIZE = 16
	USER_PUBLICKEY = " : Public Key"
	USER_VERIFYKEY = " : Verify Key"
	ENCKEY = "EncKey"
	AUTHKEY = "AuthKey"

	ERROR_LOOKUP_UUID = "ERROR: No such UUID Found"
	ERROR_LOOKUP_USERNAME = "ERROR: Username not found in public Keystore"
	ERROR_LOOKUP_INVALID_CREDENTIALS = "ERROR: Invalid Username / Password Combination"
	ERROR_LOOKUP_FILENAME = "ERROR: Cannot find file"
	ERROR_LOOKUP_FILE_NOT_OWNED = "Error: File is not owned"

	ERROR_GENERATE_PRIVATE_KEYS = "ERROR: Symmetric / Authentication Key Generation Error"
	ERROR_GENERATE_KEY_HMAC = "ERROR: Symmetric Key Generation from HMAC Error"
	ERROR_GENERATE_PUBLIC_KEYS = "ERROR: PKE / DS Key generation Error"

	ERROR_INTEGRITY_SYMMETRIC = "ERROR: Symmetric Encrypted Data Integrity violated (MAC tag Violation)"
	ERROR_INTEGRITY_ASYMMETRIC = "ERROR: Asymmetric Encrypted Data Integrity violated (Digital Signature Violation)"

	ERROR_SHARING_DUPLICATE_FILE = "Error: File with that name already exists"
)

// The structure definition for a user record (client-side)
// Note: Contains 
type User struct {
	Username string
	Password string
	PrimarySalt []byte

	AsymDecryptKey userlib.PKEDecKey
	AsymSignKey userlib.DSSignKey

	OwnedFiles map[string]Pointer
	SharedFiles map[string]Pointer
	Permissions map[string]map[string]Pointer
}

// Structure that representing an encrypted user that is stored in the datastore
type StoredUser struct {
	HashedPassword []byte
	HashSalt []byte
	PrimarySalt []byte
	Tag []byte
	EncryptedUserBytes []byte
}

// Generic encrypted data block for both private and public encryption schemes
// Data is marshaled before and after use of this struct
type EncryptedDataBlock struct {
	Ciphertext []byte
	Authentication []byte
}

// A pointer in this system represents a UUID (the pointer) to a location in the datastore
// The data located at this UUID is encrypted with EncKey and AuthKey
type Pointer struct {
	UUID uuid.UUID
	EncKey []byte
	AuthKey []byte
}

// Similar to a FAT file system, a file has 'two halves'. Each data block of a file is associated
// with a fileblock (similar to an entry in a FAT entry). The fileblock serves several purposes
//	1. Encryption of the data itself is streamlined
//	2. Holds metadata listed below allowing for easy access + traversal
//	3. Hides the file length (segment length as well)
//	4. Efficient if actual data need not be loaded in (just metadata)
type FileBlock struct {
	DataPointer Pointer
	NextBlockPointer Pointer
	LastBlockPointer Pointer
	First bool
	Last bool
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

/**
* Notes:
* - preconditions: 
*		- passwords have sufficient entropy ( attackers cannot guess a password) however two honest users may use the same password
* 		- usernames are unique 
* - Other considerations:
		- being stateless implies we have to recover everything from username + password (including UUID)
		- A salt should ideally be random long and unique though it need not be private
*/
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	userdata.Username = username
	userdata.Password = password
	userdata.PrimarySalt = userlib.RandomBytes(AESKEYSIZE)

	if err = userdata.generatePublicKeys(); err != nil {
		return userdataptr, err
	}

	userdata.OwnedFiles = map[string]Pointer{}
	userdata.SharedFiles = map[string]Pointer{}
	userdata.Permissions = map[string]map[string]Pointer{}

	return &userdata, storeUser(userdata)
}

func storeUser(userdata User) (err error) {
	var toStore StoredUser
	primaryKey := userlib.Argon2Key([]byte(userdata.Password), userdata.PrimarySalt, AESKEYSIZE)
	encKey, authKey, privKeyGenError := generateUserPrivateKeys(primaryKey)
	if privKeyGenError != nil {
		return privKeyGenError
	}

	toStore.PrimarySalt = userdata.PrimarySalt
	toStore.HashSalt = userlib.RandomBytes(AESKEYSIZE)
	toStore.HashedPassword = userlib.Argon2Key([]byte(userdata.Password), toStore.HashSalt, AESKEYSIZE)

	tag, tagErr := userlib.HMACEval(authKey, append(append(toStore.HashedPassword, toStore.HashSalt...), userdata.PrimarySalt...))
	if tagErr != nil {
		return tagErr
	}

	toStore.Tag = tag

	userBytes, marshalUserErr := json.Marshal(userdata)
	if marshalUserErr != nil {
		return marshalUserErr
	}

	encryptedUserBytes, encAuthErr := encryptThenAuthenticate(encKey, authKey, userBytes)
	if encAuthErr != nil {
		return encAuthErr
	}

	toStore.EncryptedUserBytes = encryptedUserBytes

	storedUserBytes, marshalStoredUser := json.Marshal(toStore)
	if marshalStoredUser != nil {
		return marshalStoredUser
	}

	UUID, _ := uuid.FromBytes(userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), AESKEYSIZE)[:AESKEYSIZE])
	userlib.DatastoreSet(UUID, storedUserBytes)
	return nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	UUID, _ := uuid.FromBytes(userlib.Argon2Key([]byte(password), []byte(username), AESKEYSIZE)[:AESKEYSIZE])

	storedUserBytes, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return userdataptr, errors.New(strings.ToTitle(ERROR_LOOKUP_UUID))
	}

	var storedUser StoredUser
	if unmarshalStoredUserErr := json.Unmarshal(storedUserBytes, &storedUser); unmarshalStoredUserErr != nil {
		return userdataptr, unmarshalStoredUserErr
	}

	hashedPassword := userlib.Argon2Key([]byte(password), storedUser.HashSalt, uint32(userlib.AESKeySize))
	if !userlib.HMACEqual(hashedPassword, storedUser.HashedPassword) {
		return &userdata, errors.New(strings.ToTitle(ERROR_LOOKUP_INVALID_CREDENTIALS))
	}

	primaryKey := userlib.Argon2Key([]byte(password), storedUser.PrimarySalt, uint32(userlib.AESKeySize))
	encKey, authKey, privKeyGenError := generateUserPrivateKeys(primaryKey)
	if privKeyGenError != nil {
		return &userdata, privKeyGenError
	}

	calculatedTag, macTagErr := userlib.HMACEval(authKey, append(append(storedUser.HashedPassword, storedUser.HashSalt...), storedUser.PrimarySalt...))
	if macTagErr != nil {
		return &userdata, macTagErr
	}

	if !userlib.HMACEqual(calculatedTag, storedUser.Tag) {
		return &userdata, errors.New(strings.ToTitle(ERROR_INTEGRITY_SYMMETRIC))
	}

	decrpytedUserBytes, authDecErr := authenticateThenDecrypt(encKey, authKey, storedUser.EncryptedUserBytes)
	if authDecErr != nil {
		return &userdata, authDecErr
	}

	return &userdata, json.Unmarshal(decrpytedUserBytes, &userdata)
}

// This stores a file in the datastore.
//
// The name and length of the file should NOT be revealed to the datastore!
// Note: guarenteed to be called once per user given a filename
func (userdata *User) StoreFile(filename string, data []byte) {
	dataPointer := generateRandomPointer()
	fileBlockPointer := generateKeyedPointer(dataPointer)
	sharedPointer := generateRandomPointer()
	fileBlock := FileBlock{dataPointer, Pointer{}, fileBlockPointer, true, true}

	setData(dataPointer, data)
	userdata.setFileBlock(fileBlockPointer, fileBlock)
	userdata.setFileBlockPointer(sharedPointer, fileBlockPointer)

	userdata.OwnedFiles[filename] = sharedPointer
	userdata.Permissions[filename] = map[string]Pointer{}
	userdata.Permissions[filename][userdata.Username] = sharedPointer
	storeUser(*userdata)
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	firstBlockPointer, _, lookUpPtrErr := userdata.getFileBlockPointer(filename)
	if lookUpPtrErr != nil {
		return lookUpPtrErr
	}

	firstFileBlock, lookupFirstBlockErr := userdata.getFileBlock(firstBlockPointer)
	if lookupFirstBlockErr != nil {
		return lookupFirstBlockErr
	}

	lastFileBlockPointer := firstFileBlock.LastBlockPointer
	lastFileBlock, lookupLastBlockErr := userdata.getFileBlock(lastFileBlockPointer)
	if lookupLastBlockErr != nil {
		return lookupLastBlockErr
	}

	newDataPointer := generateKeyedPointer(firstBlockPointer)
	newFileBlockPointer := generateKeyedPointer(firstBlockPointer)

	newFileBlock := FileBlock{newDataPointer, Pointer{}, newFileBlockPointer, false, true}

	lastFileBlock.NextBlockPointer = newFileBlockPointer
	lastFileBlock.Last = false

	if lastFileBlock.First {
		lastFileBlock.LastBlockPointer = newFileBlockPointer
		firstFileBlock = lastFileBlock
	}

	firstFileBlock.LastBlockPointer = newFileBlockPointer

	if setErr := setData(newDataPointer, data); setErr != nil {
		return setErr
	}

	if setFirstErr := userdata.setFileBlock(firstBlockPointer, firstFileBlock); setFirstErr != nil {
		return setFirstErr
	}

	if setLastErr := userdata.setFileBlock(lastFileBlockPointer, lastFileBlock); setLastErr != nil {
		return setLastErr
	}

	if setNewErr := userdata.setFileBlock(newFileBlockPointer, newFileBlock); setNewErr != nil {
		return setNewErr
	}

	return nil
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
// This function should return the latest version of the file data if it exists. In the case that the file
// doesn’t exist, or if it appears to have been tampered with, return nil as the data and trigger an
// error
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileBlockPointer, _, lookUpPtrErr := userdata.getFileBlockPointer(filename)
	if lookUpPtrErr != nil {
		return nil, lookUpPtrErr
	}

	fileBlock, lookupFileBlockErr := userdata.getFileBlock(fileBlockPointer)
	for ;; fileBlock, lookupFileBlockErr = userdata.getFileBlock(fileBlock.NextBlockPointer){
		if lookupFileBlockErr != nil {
			return nil, lookupFileBlockErr
		}
		dataBytes, getErr := getData(fileBlock.DataPointer)
		if getErr != nil {
			return nil, getErr
		}
		data = append(data, dataBytes...)
		if fileBlock.Last {
			break
		}
	}
	return data, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (magic_string string, err error) {
	fileBlockPointer, owned, lookUpPtrErr := userdata.getFileBlockPointer(filename)
	if lookUpPtrErr != nil {
		return magic_string, lookUpPtrErr
	}

	var toShare Pointer
	if owned {
		toShare = generateRandomPointer()
		if setErr := userdata.setFileBlockPointer(toShare, fileBlockPointer); setErr != nil {
			return magic_string, setErr
		}
		userdata.Permissions[filename][recipient] = toShare
	} else {
		toShare, _, _, err = userdata.getSharedPointer(filename)
		if err != nil {
			return magic_string, err
		}
	}

	if err = storeUser(*userdata); err != nil {
		return magic_string, err
	}
	return userdata.publicEncryptSign(toShare, recipient)
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string, magic_string string) error {
	if _, _, owned, _ := userdata.getSharedPointer(filename); owned {
		return errors.New(strings.ToTitle(ERROR_SHARING_DUPLICATE_FILE))
	}

	sharedPointer, publicErr := userdata.publicAuthenticateDecrypt(magic_string, sender)
	if publicErr != nil {
		return publicErr
	}

	userdata.SharedFiles[filename] = sharedPointer
	return storeUser(*userdata)
}

// Removes target user's access.
func (userdata *User) RevokeFile(filename string, target_username string) (err error) {
	// Find this file (error if not found)
	// Find this user (error if not found)
	// Generate a new key pair for document (FileBlockPointer)
	// Replace all that have been shared including self but excluding target_username
	// Re-encrypt fileBlock and text data using new key pair
		// Load the file
		// Delete the file
		// re-encrypt the file and store the new key where it belongs (use permissions map)

	fileBlockPointer, owned, lookUpPtrErr := userdata.getFileBlockPointer(filename)
	switch {
	case lookUpPtrErr != nil:
		return lookUpPtrErr
	case !owned:
		return errors.New(strings.ToTitle(ERROR_LOOKUP_FILE_NOT_OWNED))
	}
	if _, target_username_found := userdata.Permissions[filename][target_username]; !target_username_found {
		return
	}

	data, loadErr := userdata.LoadFile(filename)
	if loadErr != nil {
		return loadErr
	}

	for {
		fileBlock, lookupFileBlockErr := userdata.getFileBlock(fileBlockPointer)
		if lookupFileBlockErr != nil {
			return lookupFileBlockErr
		}

		nextBlockPointer := fileBlock.NextBlockPointer
		last := fileBlock.Last
		userlib.DatastoreDelete(fileBlock.DataPointer.UUID)
		userlib.DatastoreDelete(fileBlockPointer.UUID)

		fileBlockPointer = nextBlockPointer
		if last {
			break
		}
	}

	_dataPointer := generateRandomPointer()
	_fileBlockPointer := generateKeyedPointer(_dataPointer)
	_sharedPointer, _, _, _ := userdata.getSharedPointer(filename)
	_fileBlock := FileBlock{_dataPointer, Pointer{}, _fileBlockPointer, true, true}

	setData(_dataPointer, data)
	userdata.setFileBlock(_fileBlockPointer, _fileBlock)
	userdata.setFileBlockPointer(_sharedPointer, _fileBlockPointer)

	newFileBlockPointer, _, lookUpNewPtrErr := userdata.getFileBlockPointer(filename)
	if lookUpNewPtrErr != nil {
		return lookUpNewPtrErr
	}

	delete(userdata.Permissions[filename], target_username)

	for _, sharedPointer := range userdata.Permissions[filename] {
		if err = userdata.setFileBlockPointer(sharedPointer, newFileBlockPointer); err != nil {
			return err
		}
	}

	return storeUser(*userdata)
}

/*
********************************************
**           Datastore Functions          **
********************************************
*/

func getData(ptr Pointer) (plaintextBytes []byte, err error) {
	encryptedDataBytes, found := userlib.DatastoreGet(ptr.UUID)
	if !found {
		return plaintextBytes, errors.New(strings.ToTitle(ERROR_LOOKUP_UUID))
	}

	plaintextBytes, authDecErr := authenticateThenDecrypt (ptr.EncKey, ptr.AuthKey, encryptedDataBytes)
	return plaintextBytes, authDecErr
}

func setData(ptr Pointer, plaintextBytes []byte) (err error) {
	encryptedDataBytes, encAuthErr := encryptThenAuthenticate(ptr.EncKey, ptr.AuthKey, plaintextBytes)
	if encAuthErr != nil {
		return encAuthErr
	}
	userlib.DatastoreSet(ptr.UUID, encryptedDataBytes)
	return
}

func generateRandomPointer() (ptr Pointer){
	ptr.UUID = uuid.New()
	ptr.EncKey = userlib.RandomBytes(AESKEYSIZE)
	ptr.AuthKey = userlib.RandomBytes(AESKEYSIZE)
	return ptr
}

func generateKeyedPointer(original Pointer) (ptr Pointer){
	ptr.UUID = uuid.New()
	ptr.EncKey = original.EncKey
	ptr.AuthKey = original.AuthKey
	return ptr
}

func (userdata *User) getSharedPointer(filename string) (sharedPointer Pointer, owned bool, present bool, err error) {
	sharedPointer, present = userdata.OwnedFiles[filename]
	if present {
		return sharedPointer, true, true, nil
	} else {
		if sharedPointer, present = userdata.SharedFiles[filename]; present {
			return sharedPointer, false, true, nil
		} else {
			return sharedPointer, owned, false, errors.New(strings.ToTitle(ERROR_LOOKUP_FILENAME))
		}
	}
}

func (userdata *User) getFileBlockPointer(filename string) (fileBlockPointer Pointer, owned bool, err error){
	sharedPtr, _owned, present, ptrLookUpErr := userdata.getSharedPointer(filename)
	if ptrLookUpErr != nil {
		return fileBlockPointer, _owned, ptrLookUpErr
	}
	if !present {
		return fileBlockPointer, _owned, errors.New(strings.ToTitle(ERROR_LOOKUP_FILENAME))
	}
	fileBlockPointerBytes, fileBlockPointerGetError := getData(sharedPtr)
	if fileBlockPointerGetError != nil {
		return fileBlockPointer, _owned, fileBlockPointerGetError
	}
	unmarshalFileBlockPtrErr := json.Unmarshal(fileBlockPointerBytes, &fileBlockPointer)
	return fileBlockPointer, _owned, unmarshalFileBlockPtrErr
}

func (userdata *User) setFileBlockPointer(sharedPointer Pointer, fileBlockPointer Pointer) (err error) {
	pointerBytes, marshalErr := json.Marshal(fileBlockPointer)
	if marshalErr != nil {
		return marshalErr
	}
	return setData(sharedPointer, pointerBytes)
}

func (userdata *User) getFileBlock(fileBlockPointer Pointer) (fileBlock FileBlock, err error) {
	dataBytes, getErr := getData(fileBlockPointer)
	if getErr != nil {
		return fileBlock, getErr
	}
	return fileBlock, json.Unmarshal(dataBytes, &fileBlock)
}

func (userdata *User) setFileBlock(fileBlockPointer Pointer, fileBlock FileBlock) (err error) {
	blockBytes, marshalErr := json.Marshal(fileBlock)
	if marshalErr != nil {
		return marshalErr
	}
	return setData(fileBlockPointer, blockBytes)
}

/*
********************************************
**         Public Key Encryption          **
********************************************
*/
func (userdata *User) generatePublicKeys() (publicKeyGenError error) {
	asymEncryptKey, asymDecryptKey, pkeError := userlib.PKEKeyGen()
	asymSignKey, asymVerifyKey, dsError := userlib.DSKeyGen()

	switch {
	case pkeError != nil || dsError != nil:
		return errors.New(strings.ToTitle(ERROR_GENERATE_PUBLIC_KEYS))
	default:
		userlib.KeystoreSet(userdata.Username + USER_PUBLICKEY, asymEncryptKey)
		userlib.KeystoreSet(userdata.Username + USER_VERIFYKEY, asymVerifyKey)
		userdata.AsymDecryptKey, userdata.AsymSignKey = asymDecryptKey, asymSignKey
	}
	return nil
}

func (userdata *User) publicEncryptSign(sharedPointer Pointer, recipient string) (magic_string string, err error) {
	pointerBytes, marshalErr := json.Marshal(sharedPointer)
	if marshalErr != nil {
		return magic_string, marshalErr
	}

	recipientAsymEncryptKey, foundRecipient := userlib.KeystoreGet(recipient + USER_PUBLICKEY)
	if !foundRecipient {
		return magic_string, errors.New(strings.ToTitle(ERROR_LOOKUP_USERNAME))
	}

	ciphertext, encErr := userlib.PKEEnc(recipientAsymEncryptKey, pointerBytes)
	if encErr != nil {
		return magic_string, encErr
	}

	signature, signErr := userlib.DSSign(userdata.AsymSignKey, ciphertext)
	if signErr != nil {
		return magic_string, signErr
	}

	magic := EncryptedDataBlock{
		Ciphertext : ciphertext,
		Authentication : signature,
	} 

	magic_bytes, marshaMagicErr := json.Marshal(magic)

	if marshaMagicErr != nil {
		return magic_string, marshaMagicErr
	}

	return string(magic_bytes), nil
} 

func (userdata *User) publicAuthenticateDecrypt(magic_string string, sender string) (sharedPointer Pointer, err error) {
	var encryptedDataBlock EncryptedDataBlock
	if unmarshalErr := json.Unmarshal([]byte(magic_string), &encryptedDataBlock); unmarshalErr != nil {
		return sharedPointer, unmarshalErr
	}

	senderAsymVerifyKey, foundSender := userlib.KeystoreGet(sender + USER_VERIFYKEY)
	if !foundSender {
		return sharedPointer, errors.New(strings.ToTitle(ERROR_LOOKUP_USERNAME))
	}

	if verifyErr := userlib.DSVerify(senderAsymVerifyKey, encryptedDataBlock.Ciphertext, encryptedDataBlock.Authentication); verifyErr != nil {
		return sharedPointer, errors.New(strings.ToTitle(ERROR_INTEGRITY_ASYMMETRIC))
	}

	pointerBytes, decErr := userlib.PKEDec(userdata.AsymDecryptKey, encryptedDataBlock.Ciphertext)

	if decErr != nil {
		return sharedPointer, decErr
	}

	return sharedPointer, json.Unmarshal(pointerBytes, &sharedPointer)
}

/*
********************************************
**        Symmetric Encryption            **
**      Encrypt then Athenticate          **
********************************************
*/

func encryptThenAuthenticate (encKey []byte, authKey []byte, plaintext []byte) (encryptedDataBytes []byte, err error) {
	iv := userlib.RandomBytes(userlib.AESBlockSize)
	ciphertext := userlib.SymEnc(encKey, iv, plaintext)
	tag, hmacErr := userlib.HMACEval(authKey, ciphertext)
	if hmacErr != nil {
		return []byte{}, hmacErr
	}
	var encryptedDataBlock = EncryptedDataBlock{
		Ciphertext: ciphertext,
		Authentication: tag,
	}
	encryptedDataBytes, err = json.Marshal(encryptedDataBlock)
	if err != nil {
		return []byte{}, err 
	}
	return encryptedDataBytes, nil
}

func authenticateThenDecrypt (encKey []byte, authKey []byte, encryptedDataBytes []byte) (plaintextBytes []byte, err error) {
	var encryptedDataBlock EncryptedDataBlock
	err = json.Unmarshal(encryptedDataBytes, &encryptedDataBlock)

	calcTag, macErr := userlib.HMACEval(authKey, encryptedDataBlock.Ciphertext)
	switch {
	case macErr != nil:
		return []byte{}, macErr
	case !userlib.HMACEqual(calcTag, encryptedDataBlock.Authentication):
		return []byte{}, errors.New(strings.ToTitle(ERROR_INTEGRITY_SYMMETRIC))
	default:
		return userlib.SymDec(encKey, encryptedDataBlock.Ciphertext), nil
	}
}

func generateKeyHMAC (key []byte, input []byte) (newKey []byte, err error) {
	newKey, err = userlib.HMACEval(key, input)
	if err != nil {
		return []byte{}, errors.New(strings.ToTitle(ERROR_GENERATE_KEY_HMAC))
	}
	return newKey[:AESKEYSIZE], err
}

func generateUserPrivateKeys(primaryKey []byte) (encKey []byte, authKey []byte, err error) {
	_encKey, encKeyGenError := generateKeyHMAC(primaryKey, []byte(ENCKEY))
	_authKey, authKeyGenError := generateKeyHMAC(primaryKey, []byte(AUTHKEY))
	
	if encKeyGenError != nil || authKeyGenError != nil {
		return encKey, authKey, errors.New(strings.ToTitle(ERROR_GENERATE_PRIVATE_KEYS))
	}

	return _encKey, _authKey, nil
}

/*
********************************************
**          Misc / Debug Helpers          **
********************************************
*/

func (user *User) String() (ret string) {
	ret = "User "
	str, _ := json.MarshalIndent(user, "", "  ")
	ret += string(str)
	return trimToString(ret)
}

func log(format string, args ...string) string{
    r := strings.NewReplacer(args...)
    return r.Replace(format)
}

func trimToString(input string) (output string) {
	for _, line := range strings.Split(strings.TrimSuffix(input, "\n"), "\n") {
    	if len(line) >= 80 {
    		line = line[:75] + "...,"
    	}
    	output += (line + "\n")
	}
	return output
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}