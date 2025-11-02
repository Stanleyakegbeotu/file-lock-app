import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Upload, Lock, Unlock, CheckCircle, AlertCircle, KeyRound, FolderOpen, Plus, Archive, Trash2, Download } from 'lucide-react';

// --- CRYPTOGRAPHIC CONSTANTS ---
const ITERATIONS = 100000;
const SALT = new TextEncoder().encode('secure-locker-salt-v1');
const IV_LENGTH = 12;

// --- INDEXEDDB CONSTANTS ---
const DB_NAME = 'LockerDB';
const STORE_NAME = 'LockerData';
const METADATA_STORE = 'FileMetadata'; // New store for file metadata
const DB_VERSION = 2; // Increased version to trigger schema upgrade

// --- UTILITY FUNCTIONS (CRYPTO) ---

const deriveKeyFromPassword = async (password) => {
    const passwordData = new TextEncoder().encode(password);
    const keyMaterial = await crypto.subtle.importKey(
        'raw', passwordData, { name: 'PBKDF2' }, false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: SALT, iterations: ITERATIONS, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
};

const encryptFile = async (key, fileData) => {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const encryptedData = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv }, key, fileData
    );
    return { 
        encryptedData: new Uint8Array(encryptedData), 
        iv: iv 
    };
};

const decryptFile = async (key, encryptedData, iv) => {
    try {
        const decryptedData = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv }, key, encryptedData.buffer
        );
        return { success: true, data: new Uint8Array(decryptedData) };
    } catch (e) {
        return { success: false, data: null };
    }
};

// --- UTILITY FUNCTIONS (INDEXEDDB) ---

const openDB = () => {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);

        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: 'id' });
            }
            if (!db.objectStoreNames.contains(METADATA_STORE)) {
                 db.createObjectStore(METADATA_STORE, { keyPath: 'id' });
            }
        };

        request.onsuccess = (event) => resolve(event.target.result);
        request.onerror = (event) => reject('IndexedDB error');
    });
};

const getDBData = async (storeName, id) => {
    const db = await openDB();
    return new Promise((resolve) => {
        const transaction = db.transaction(storeName, 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.get(id);

        request.onsuccess = (event) => resolve(event.target.result?.data || event.target.result);
        request.onerror = () => resolve(null);
    });
};

const setDBData = async (storeName, data) => {
    const db = await openDB();
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(storeName, 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.put(data);

        request.onsuccess = () => resolve(true);
        request.onerror = (event) => {
            console.error('Set DB Data Error:', event.target.error);
            reject(false);
        };
    });
};

const getAllDBMetadata = async () => {
    const db = await openDB();
    return new Promise((resolve) => {
        const transaction = db.transaction(METADATA_STORE, 'readonly');
        const store = transaction.objectStore(METADATA_STORE);
        const request = store.getAll();

        request.onsuccess = (event) => resolve(event.target.result);
        request.onerror = () => resolve([]);
    });
};

// --- STATUS COMPONENTS ---

const StatusIcon = ({ status }) => {
    switch (status) {
        case 'IDLE':
            return <FolderOpen className="w-12 h-12 text-gray-400" />;
        case 'READY':
            return <Upload className="w-12 h-12 text-indigo-500" />;
        case 'PROCESSING':
            return <Unlock className="w-12 h-12 text-yellow-500 animate-spin" />;
        case 'DONE':
            return <CheckCircle className="w-12 h-12 text-green-500" />;
        case 'ERROR':
            return <AlertCircle className="w-12 h-12 text-red-500" />;
        default:
            return null;
    }
};

// --- CORE APPLICATION COMPONENT ---

const App = () => {
    // State for Navigation and Authentication
    const [view, setView] = useState('LOGIN');
    const [password, setPassword] = useState('');
    const [isPinVisible, setIsPinVisible] = useState(false);
    const [authError, setAuthError] = useState('');
    
    // State for File System Access & Metadata
    const [lockerHandle, setLockerHandle] = useState(null);
    const [isHandleRestored, setIsHandleRestored] = useState(false);
    const fileInputRef = useRef(null);

    // State for File Locker Functionality (Dashboard)
    const [originalFile, setOriginalFile] = useState(null);
    const [lockerStatus, setLockerStatus] = useState('IDLE');
    const [message, setMessage] = useState('Select or set your Locker Folder to begin.');
    const [lockedFiles, setLockedFiles] = useState([]); 


    // --- INITIALIZATION: Restore Handle and Load Metadata ---
    const loadAppState = useCallback(async () => {
        if (typeof window.showDirectoryPicker === 'undefined') {
            setMessage('Warning: File System Access API not supported in your browser.');
            setLockerStatus('ERROR');
            setIsHandleRestored(true);
            return;
        }
        
        // 1. Restore Directory Handle
        const handle = await getDBData(STORE_NAME, 'lockerHandle');
        if (handle) {
            const permission = await handle.queryPermission({ mode: 'readwrite' });
            if (permission === 'granted') {
                setLockerHandle(handle);
                setMessage('Locker folder access restored!');
            } else {
                // If not granted, try requesting again
                const success = await handle.requestPermission({ mode: 'readwrite' });
                if (success === 'granted') setLockerHandle(handle);
            }
        }
        
        // 2. Load File Metadata
        const metadata = await getAllDBMetadata();
        setLockedFiles(metadata);

        setIsHandleRestored(true);
        if (handle) {
            setMessage(`Access restored. ${metadata.length} files locked.`);
        }
    }, []);

    useEffect(() => {
        loadAppState();
    }, [loadAppState]);


    const selectLockerFolder = async () => {
        try {
            const handle = await window.showDirectoryPicker();

            // Persist the handle reference
            await setDBData(STORE_NAME, { id: 'lockerHandle', data: handle });
            setLockerHandle(handle);
            setMessage(`Locker Folder selected: ${handle.name}. Ready to lock files.`);

        } catch (error) {
            console.error('Folder selection failed:', error);
            setMessage('Folder selection was cancelled or failed.');
        }
    };


    // --- Authentication & View Handlers ---

    const handlePasswordChange = (e) => {
        const value = e.target.value.replace(/[^0-9]/g, '');
        if (value.length <= 6) {
            setPassword(value);
            setAuthError('');
        }
    };

    const handleLogin = (e) => {
        e.preventDefault();
        if (password.length !== 6) {
            setAuthError('Password must be exactly 6 digits.');
            return;
        }
        
        if (isHandleRestored) {
            setView('DASHBOARD');
        } else {
            setAuthError('App initializing, please wait...');
        }
    };

    const handleLogout = () => {
        setOriginalFile(null);
        setPassword('');
        setLockerStatus('IDLE');
        setMessage('Select or set your Locker Folder to begin.');
        setView('LOGIN');
    };


    // --- File Locker Handlers (Dashboard) ---

    const handleFloatingSelect = () => {
        if (fileInputRef.current) {
            fileInputRef.current.click();
        }
    };

    const handleFileChange = (event) => {
        const file = event.target.files[0];
        if (file) {
            setOriginalFile(file);
            setLockerStatus('READY');
            setMessage(`File ready: ${file.name}. Click 'Lock File' to proceed.`);
        }
    };

    const moveFileToLocker = async (file, encryptedData) => {
        if (!lockerHandle) return false;
        
        try {
            // Generate a unique filename for the encrypted file 
            const encryptedFileName = `${crypto.randomUUID()}.locked`;

            // Get the handle for the encrypted file
            const fileHandle = await lockerHandle.getFileHandle(encryptedFileName, { create: true });
            
            // Write the encrypted data
            const writable = await fileHandle.createWritable();
            await writable.write(encryptedData);
            await writable.close();
            
            return encryptedFileName;

        } catch (error) {
            console.error("File System Write Failed:", error);
            setMessage(`File System Write Failed: ${error.message}`);
            return false;
        }
    }


    const handleEncrypt = async (e) => {
        e.preventDefault();
        if (!originalFile || password.length !== 6 || !lockerHandle) {
            setMessage('Error: Password, file, or Locker Folder not set.');
            setLockerStatus('ERROR');
            return;
        }

        setLockerStatus('PROCESSING');
        setMessage(`Deriving key and encrypting ${originalFile.name}...`);

        try {
            const key = await deriveKeyFromPassword(password);
            const fileData = await originalFile.arrayBuffer();
            const { encryptedData, iv } = await encryptFile(key, fileData);
            
            // 1. Save the encrypted data to the local folder
            const encryptedFileName = await moveFileToLocker(originalFile, encryptedData);

            if (encryptedFileName) {
                // 2. Save metadata to IndexedDB
                const metadata = {
                    id: crypto.randomUUID(),
                    originalName: originalFile.name,
                    fileType: originalFile.type,
                    encryptedFileName: encryptedFileName,
                    iv: Array.from(iv), // Store IV as a simple array
                    size: originalFile.size
                };
                
                await setDBData(METADATA_STORE, metadata);
                setLockedFiles(prev => [...prev, metadata]); 

                setLockerStatus('DONE');
                setMessage(`SUCCESS! '${originalFile.name}' is encrypted and saved in your Locker.`);
                setOriginalFile(null);
            } else {
                 setLockerStatus('ERROR');
            }

        } catch (error) {
            console.error("Encryption failed:", error);
            setLockerStatus('ERROR');
            setMessage(`Encryption failed. Check console for details.`);
        }
    };

    const handleDecrypt = async (fileMetadata) => {
        if (!lockerHandle || password.length !== 6) {
            // FIX: Replaced alert() with state message update
            setMessage('Error: Folder not accessible or password missing.');
            setLockerStatus('ERROR');
            return;
        }
        
        setLockerStatus('PROCESSING');
        setMessage(`Decrypting '${fileMetadata.originalName}'...`);
        
        try {
            // 1. Get the encrypted file handle
            const fileHandle = await lockerHandle.getFileHandle(fileMetadata.encryptedFileName);
            
            // 2. Read the encrypted data
            const file = await fileHandle.getFile();
            const encryptedData = await file.arrayBuffer();

            // 3. Derive the key and decrypt
            const key = await deriveKeyFromPassword(password);
            const iv = new Uint8Array(fileMetadata.iv);
            
            const { success, data: decryptedData } = await decryptFile(key, new Uint8Array(encryptedData), iv);

            if (success) {
                // 4. Offer the decrypted file back to the user
                const blob = new Blob([decryptedData], { type: fileMetadata.fileType });
                const url = URL.createObjectURL(blob);
                
                const a = document.createElement('a');
                a.href = url;
                a.download = `UNLOCKED_${fileMetadata.originalName}`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);

                setLockerStatus('DONE');
                setMessage(`SUCCESS! '${fileMetadata.originalName}' downloaded.`);
            } else {
                setLockerStatus('ERROR');
                setMessage('DECRYPTION FAILED: Invalid Password or corrupted file.');
            }

        } catch (error) {
            console.error("Decryption operation failed:", error);
            setLockerStatus('ERROR');
            setMessage(`Decryption error: Could not read file from disk.`);
        }
    };

    // The logic for playing/opening files is complex and needs a dedicated player component.
    // For now, we focus on the core security principle: download and open.
    const handleOpenInApp = (fileMetadata) => {
        setMessage(`Feature: Opening/Playing ${fileMetadata.fileType} in-app requires a media player component. Use 'Unlock & Download' for now.`);
    };

    const isReadyForLock = originalFile && password.length === 6 && lockerHandle && lockerStatus !== 'PROCESSING';


    // --- View Rendering Functions ---

    const renderLoginScreen = () => (
        <div className="w-full max-w-sm bg-white p-6 sm:p-8 rounded-xl shadow-2xl transition-all duration-300 border-t-4 border-indigo-600">
            <h1 className="text-3xl font-extrabold text-indigo-700 text-center mb-2">
                Secure Locker Access
            </h1>
            <p className="text-center text-sm text-gray-500 mb-8">
                Enter your 6-digit password to continue.
            </p>

            <form onSubmit={handleLogin} className="space-y-6">
                <div className="relative">
                    <label htmlFor="password-input" className="sr-only">6-Digit Password</label>
                    <div className="flex items-center border border-gray-300 rounded-lg shadow-sm">
                        <KeyRound className="w-5 h-5 text-gray-400 ml-3" />
                        <input
                            type={isPinVisible ? 'text' : 'password'}
                            id="password-input"
                            value={password}
                            onChange={handlePasswordChange}
                            maxLength="6"
                            pattern="\d{6}"
                            placeholder="------"
                            className="flex-grow p-3 text-center text-xl tracking-widest focus:ring-0 focus:outline-none"
                            autoComplete="off"
                            disabled={!isHandleRestored}
                        />
                        <button
                            type="button"
                            onClick={() => setIsPinVisible(!isPinVisible)}
                            className="p-3 text-gray-500 hover:text-gray-700 transition duration-150"
                        >
                            {isPinVisible ? '🙈' : '👁️'}
                        </button>
                    </div>
                </div>

                {authError && (
                    <p className="text-red-500 text-center text-sm font-medium">{authError}</p>
                )}

                <button
                    type="submit"
                    disabled={password.length !== 6 || !isHandleRestored}
                    className={`w-full py-3 rounded-xl text-white font-bold transition duration-200 shadow-lg 
                        ${password.length !== 6 || !isHandleRestored
                            ? 'bg-gray-400 cursor-not-allowed' 
                            : 'bg-indigo-600 hover:bg-indigo-700 active:shadow-none'}`}
                >
                    Access Dashboard
                </button>
            </form>
            {!isHandleRestored && (
                <p className="mt-4 text-center text-sm text-yellow-600 animate-pulse">
                    Initializing local APIs and restoring folder access...
                </p>
            )}
        </div>
    );

    const renderDashboard = () => (
        <div className="w-full max-w-lg bg-white p-6 sm:p-8 rounded-xl shadow-2xl transition-all duration-300 relative min-h-[400px]">
            {/* Header and Logout */}
            <div className="flex justify-between items-center mb-6 border-b pb-4">
                <h2 className="text-2xl font-bold text-indigo-700">
                    Locker Dashboard
                </h2>
                <button
                    onClick={handleLogout}
                    className="text-sm text-red-500 font-medium hover:text-red-700 transition duration-150"
                >
                    Logout
                </button>
            </div>
            
            {/* Folder Setup Area */}
            <div className="p-4 rounded-lg bg-indigo-50 border-2 border-dashed border-indigo-300 mb-6">
                <div className="flex justify-between items-center">
                    <div className="flex items-center space-x-2">
                        <Archive className="w-5 h-5 text-indigo-600" />
                        <span className="font-semibold text-indigo-700">Locker Folder:</span>
                    </div>
                    {lockerHandle ? (
                        <span className="text-sm text-green-600 font-medium truncate">
                            {lockerHandle.name} (Ready)
                        </span>
                    ) : (
                        <button
                            onClick={selectLockerFolder}
                            className="bg-indigo-600 text-white text-xs font-semibold px-3 py-1 rounded-full hover:bg-indigo-700 transition duration-150"
                        >
                            Select Locker Folder
                        </button>
                    )}
                </div>
                {!lockerHandle && (
                    <p className="text-sm text-gray-600 mt-2">
                        Please select a folder where all encrypted files will be stored.
                    </p>
                )}
            </div>

            {/* Status and Action Area */}
            <div className="flex flex-col items-center space-y-4 mb-8">
                <StatusIcon status={lockerStatus} />
                <p className={`text-center font-semibold text-base px-2 
                    ${lockerStatus === 'DONE' ? 'text-green-600' : 
                      lockerStatus === 'ERROR' ? 'text-red-600' : 'text-gray-700'}`}>
                    {message}
                </p>
            </div>

            {/* Hidden File Input (Tied to floating button) */}
            <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileChange}
                className="hidden"
            />

            {/* File List */}
            <div className="mb-12">
                <h3 className="text-lg font-semibold text-gray-700 mb-2">
                    Locked Files ({lockedFiles.length})
                </h3>
                {lockedFiles.length > 0 ? (
                    <div className="space-y-3 max-h-60 overflow-y-auto pr-2">
                        {lockedFiles.map((file) => (
                            <div key={file.id} className="bg-gray-50 p-3 rounded-xl shadow-sm flex flex-col sm:flex-row justify-between items-start sm:items-center text-sm border">
                                <span className="font-medium truncate w-full sm:w-1/2 text-indigo-700">
                                    {file.originalName}
                                </span>
                                <div className="flex space-x-2 mt-2 sm:mt-0">
                                    <button
                                        onClick={() => handleOpenInApp(file)}
                                        className="flex items-center px-3 py-1 bg-yellow-500 text-white rounded-full hover:bg-yellow-600 transition duration-150 text-xs font-semibold"
                                    >
                                        <FolderOpen className="w-3 h-3 mr-1" /> Open/Play
                                    </button>
                                    <button
                                        onClick={() => handleDecrypt(file)}
                                        className="flex items-center px-3 py-1 bg-green-500 text-white rounded-full hover:bg-green-600 transition duration-150 text-xs font-semibold"
                                    >
                                        <Download className="w-3 h-3 mr-1" /> Unlock & Download
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="text-gray-500 text-center py-4 border rounded-lg border-dashed">
                        No files currently locked. Click the '+' button to add one.
                    </p>
                )}
            </div>

            {/* Floating Action Button (File Selector) */}
            {lockerHandle && (
                <button
                    onClick={handleFloatingSelect}
                    className="fixed right-6 bottom-6 md:right-10 md:bottom-10 w-14 h-14 rounded-full bg-indigo-600 text-white shadow-2xl flex items-center justify-center hover:bg-indigo-700 transition duration-300 z-10"
                    title="Add file to locker"
                >
                    <Plus className="w-8 h-8" />
                </button>
            )}

            {/* Lock Action Button (Processes the file selected by the floating button) */}
            {originalFile && (
                 <button
                    onClick={handleEncrypt}
                    disabled={!isReadyForLock}
                    className={`w-full py-3 rounded-xl text-white font-bold transition duration-200 shadow-lg 
                        ${!isReadyForLock 
                            ? 'bg-gray-400 cursor-not-allowed' 
                            : 'bg-indigo-600 hover:bg-indigo-700 active:shadow-none'}`}
                >
                    LOCK FILE NOW: {originalFile.name}
                </button>
            )}

            <p className="mt-8 text-xs text-center text-gray-400">
                Data is stored in your selected local folder (encrypted) and browser's IndexedDB (metadata).
            </p>
        </div>
    );


    return (
        <div className="min-h-screen bg-gray-100 p-4 sm:p-8 flex justify-center items-start pt-10">
            {view === 'LOGIN' ? renderLoginScreen() : renderDashboard()}
        </div>
    );
};

export default App;
