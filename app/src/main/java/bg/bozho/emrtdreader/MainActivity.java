package bg.bozho.emrtdreader;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Bitmap;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.widget.ImageView;
import android.widget.TextView;

import net.sf.scuba.smartcards.CardService;
import net.sf.scuba.smartcards.CardServiceException;
import net.sf.scuba.tlv.TLVOutputStream;

import org.jmrtd.BACKeySpec;
import org.jmrtd.ChipAuthenticationResult;
import org.jmrtd.DESedeSecureMessagingWrapper;
import org.jmrtd.PassportService;
import org.jmrtd.TerminalAuthenticationResult;
import org.jmrtd.Util;
import org.jmrtd.cert.CVCAuthorizationTemplate;
import org.jmrtd.cert.CVCPrincipal;
import org.jmrtd.cert.CardVerifiableCertificate;
import org.jmrtd.lds.COMFile;
import org.jmrtd.lds.CVCAFile;
import org.jmrtd.lds.DG14File;
import org.jmrtd.lds.DG15File;
import org.jmrtd.lds.DG1File;
import org.jmrtd.lds.DG2File;
import org.jmrtd.lds.FaceImageInfo;
import org.jmrtd.lds.FaceInfo;
import org.jmrtd.lds.LDS;
import org.jmrtd.lds.LDSFileUtil;
import org.jmrtd.lds.MRZInfo;
import org.jmrtd.lds.SODFile;
import org.spongycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {

    private NfcAdapter mNfcAdapter;
    private PendingIntent mNfcPendingIntent;
    private IntentFilter[] mNdefExchangeFilters;
    private IntentFilter[] mWriteTagFilters;
    private boolean mResumed;
    public String TAG = "EMRTD >>> ";
    boolean isNewDoc = true;

    TextView dg1TextView;
    ImageView dg2ImageView;
    PassportService ps = null;
    LDS psLDS;

    String mrzDG1;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
        mNfcPendingIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        // Intent filters for reading a note from a tag or exchanging over p2p.
        IntentFilter ndefDetected = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        IntentFilter tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        try {
            ndefDetected.addDataType("text/plain");
        } catch (IntentFilter.MalformedMimeTypeException e) {
        }
        mNdefExchangeFilters = new IntentFilter[]{ndefDetected, tagDetected};

        // Intent filters for writing to a tag

        mWriteTagFilters = new IntentFilter[]{tagDetected};

        dg1TextView = (TextView) findViewById(R.id.dg1);
        dg2ImageView = (ImageView) findViewById(R.id.dg2);

    }

    @Override
    protected void onResume() {
        super.onResume();
        mResumed = true;
        Intent i = new Intent(getApplicationContext(), this.getClass());
        i.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_UPDATE_CURRENT);
        String[][] filter = new String[][]{new String[]{"android.nfc.tech.IsoDep"}};
        mNfcAdapter.enableForegroundDispatch(this, pendingIntent, null, filter);

        Intent intent = getIntent();
        String action = intent.getAction();
        if (NfcAdapter.ACTION_TECH_DISCOVERED.equals(action)) {
            Tag t = intent.getExtras().getParcelable(NfcAdapter.EXTRA_TAG);
            if (Arrays.asList(t.getTechList()).contains("android.nfc.tech.IsoDep")) {
                handleIsoDepFound(IsoDep.get(t));
            }
        } else {
            Log.w(TAG, "resolveIntent >> unhandled action " + action);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        mResumed = false;
        mNfcAdapter.disableForegroundDispatch(this);

    }

    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        // getIntent() should always return the most recent
        setIntent(intent);

    }

    private void handleIsoDepFound(IsoDep isoDep) {
        Log.d(TAG, "handleIsoDepFound " + isoDep);
        try {
            isoDep.setTimeout(30000);
            new AsyncPassportCreate().execute(isoDep);
        } catch (Exception ex) {
            Log.e(TAG, "error " + ex.toString());
        }
    }


    class AsyncPassportCreate extends AsyncTask<IsoDep, String, Void> {
        public String TAG = "AsyncPassportCreate>>";

        @Override
        protected Void doInBackground(IsoDep... params) {
            if (isNewDoc) {
                ps = null;
                InputStream isCom = null;
                InputStream isSOD = null;
                InputStream isDG1 = null;
                InputStream isDG2 = null;
                InputStream isDG15 = null;
                InputStream isDG14 = null;
                InputStream isCVCA = null;
                psLDS = new LDS();
                try {
                    BACKeySpec bacKey = new BACKeySpec() {

                        @Override
                        public String getDocumentNumber() {
                            //return "XR0302869";
                            // return "SA8001322";
                            return "XR0302461";
                            //return "556031304";
                            //return "L833902C"; //bac fail
                            //return "O3000273";
                            //return "P100001";
                        }

                        @Override
                        public String getDateOfBirth() {
                            //return "830916";
                            //return "870503";
                            return "830916";
                            //return "760412";
                            //return "820112";
                            //return "930818";
                            //return "671123";
                        }

                        @Override
                        public String getDateOfExpiry() {
                            //return "170925";
                            //return "170620";
                            return "170925";
                            //return "180412";
                            //return "200112";
                            //return "180324";
                            //return "161222";
                        }
                    };
                    Log.i(TAG, "BAC Key=" + bacKey.getDocumentNumber());
                    IsoDep nfc = params[0];
                    //IsoDep nfc = IsoDep.get(tag);
                    CardService cs = CardService.getInstance(nfc);
                    ps = new PassportService(cs);
                    ps.open();

                    ps.sendSelectApplet(false);

                    ps.doBAC(bacKey);

                    //COM File
                    isCom = ps.getInputStream(PassportService.EF_COM);
                    COMFile com = (COMFile) LDSFileUtil.getLDSFile(PassportService.EF_COM, isCom);

                    // Basic data
                    //DG1
                    isDG1 = ps.getInputStream(PassportService.EF_DG1);
                    DG1File dg1 = (DG1File) LDSFileUtil.getLDSFile(PassportService.EF_DG1, isDG1);

                    isSOD = ps.getInputStream(PassportService.EF_SOD);
                    SODFile sod = (SODFile) LDSFileUtil.getLDSFile(PassportService.EF_SOD, isSOD);
                    isDG15 = ps.getInputStream(PassportService.EF_DG15);
                    DG15File dg15 = (DG15File) LDSFileUtil.getLDSFile(PassportService.EF_DG15, isDG15);
                    try {
                        isCVCA = ps.getInputStream(PassportService.EF_CVCA);
                        CVCAFile cvcaFile = (CVCAFile) LDSFileUtil.getLDSFile(PassportService.EF_CVCA, isCVCA);
                        if (cvcaFile != null) {
                            CVCPrincipal altCARef = cvcaFile.getAltCAReference();
                            CVCPrincipal caRef = cvcaFile.getCAReference();
                            if (altCARef != null)
                                Log.i(TAG, "altCARef>> Mnemonic=" + altCARef.getMnemonic() + "; name=" + altCARef.getName() + "; SeqNumber=" + altCARef.getSeqNumber() + "; country=" + altCARef.getCountry());
                            else
                                Log.i(TAG, "altCARef is null");
                            if (caRef != null)
                                Log.i(TAG, "caRef>> Mnemonic=" + caRef.getMnemonic() + "; name=" + caRef.getName() + "; SeqNumber=" + caRef.getSeqNumber() + "; country=" + caRef.getCountry());
                            else
                                Log.i(TAG, "caRef is null");
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }

//
//                    isDG14 = ps.getInputStream(PassportService.EF_DG14);
//                    DG14File dg14 = (DG14File) LDSFileUtil.getLDSFile(PassportService.EF_DG14, isDG14);


                    try {
                        isDG14 = ps.getInputStream(PassportService.EF_DG14);
                        DG14File dg14File = (DG14File) LDSFileUtil.getLDSFile(PassportService.EF_DG14, isDG14);
                        Log.i(TAG, dg14File.toString());

//                        Map<BigInteger, PublicKey> keyInfo = dg14File.getChipAuthenticationPublicKeyInfos();
//                        Map.Entry<BigInteger, PublicKey> entry = keyInfo.entrySet().iterator().next();
//
//                        Log.i(TAG, "keyInfo.getKeySet=" + keyInfo.keySet().toString() + "; keyInfo.getValues=" + keyInfo.values().toString());
//
//                        Log.i(TAG, "entry.getKey=" + entry.getKey() + "; entry.getValu=" + entry.getValue());
//
//
//                        Map<BigInteger, String> info = dg14File.getChipAuthenticationInfos();
//                        Log.i(TAG, "info.getKeySet=" + info.keySet().toString() + "; info.getValues=" + info.values().toString());
//
//                        Map<BigInteger, String> caInfos=dg14File.getChipAuthenticationInfos();
//                        Log.i(TAG, "caInfos=" + caInfos.toString());
//
//                        //ps.doCA()
//
//
//                        PrivateKey terminalKey = null;
//                        List<CardVerifiableCertificate> cvCertificates = null;
//                        Map<BigInteger, PublicKey> publicKeyMap = dg14File.getChipAuthenticationPublicKeyInfos();
//                        BigInteger cardPublicKeyId = BigInteger.valueOf(-1);
//                        List<Short> cvcaFIDs = dg14File.getCVCAFileIds();
//                        Log.i(TAG, "cvcaFIDs=" + cvcaFIDs);
//
//                        Log.i(TAG, "publicKeyMap=" + publicKeyMap);
//                        Log.i(TAG, "terminalKey=" + terminalKey);
//                        Log.i(TAG, "cvCertificates=" + cvCertificates);
//                        Log.i(TAG, "cardPublicKeyId=" + cardPublicKeyId);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }


                    // Log.i(TAG, "DG1=" + dg1.toString());

                    isDG2 = ps.getInputStream(PassportService.EF_DG2);
                    DG2File dg2 = (DG2File) LDSFileUtil.getLDSFile(PassportService.EF_DG2, isDG2);

                    psLDS.add(com);
                    psLDS.add(dg1);
                    psLDS.add(sod);
//                    psLDS.add(cvca);
                    psLDS.add(dg15);
                    psLDS.add(dg2);

                } catch (CardServiceException e) {
                    e.printStackTrace();
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        if (isDG1 != null)
                            isDG1.close();
                        if (isSOD != null)
                            isSOD.close();
                        if (isCom != null)
                            isCom.close();
                        if (isDG2 != null)
                            isDG2.close();
                        if (isDG15 != null)
                            isDG15.close();
                        if (isDG14 != null)
                            isDG14.close();
                        if (isCVCA != null)
                            isCVCA.close();

                        //isCvca.close();
                        ps.close();
                    } catch (Exception ex) {
                        ex.printStackTrace();
                    }
                }
            }
            return null;
        }

        @Override
        protected void onPostExecute(Void v) {
            // if (passport == null) { throw new IllegalArgumentException("Failed to get a passport"); }
            if (ps == null) {
                // goto bac entry activity
                System.err.println("BAC denied!");
                isNewDoc = true;
            } else {
                //handlePassportCreated(ps);
                isNewDoc = false;
                //COMFile c = null;
                try {
                    new AsyncPassportInterpret().execute();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
        }
    }
/*
    private void handlePassportCreated(final PassportService passportService) {
        if (passportService == null) {
            throw new IllegalArgumentException("Failed to get a passport");
        }

        final LDS lds = passportService.getLDS();

        isDisplaying = true;
        overallProgressBar.setVisibility(View.VISIBLE);
        overallProgressBar.setProgress(lds.getPosition());
        overallProgressBar.setMax(lds.getLength());

        progressHandler = new Handler() {
            @Override
            public void handleMessage(Message msg) {
                // get the value from the Message
                int progress = msg.arg1;
                overallProgressBar.setProgress(progress);
            }
        };

        new Thread(new Runnable() {

            public void run() {
                try {
                    while (isDisplaying) {
                        int progress = lds.getPosition();
                        Message message = new Message();
                        message.arg1 = progress;
                        progressHandler.sendMessage(message);
                        Thread.sleep(1000);
                    }
                } catch (InterruptedException ie) {
                    // NOTE: On interrupt we leave loop
                    Logging.e(TAG + "handlePassportCreated >> Thread >> On interrupt we leave loop");
                }
            }
        }).start();

        new AsyncPassportInterpret().execute(passport);
    }*/

    class AsyncPassportInterpret extends AsyncTask<PassportService, Void, Void> {
        PassportService passportService;

        List<FaceImageInfo> allFaceImageInfos = new ArrayList<FaceImageInfo>();

        @Override
        protected Void doInBackground(PassportService... params) {
            try {
                //passportService = params[0];
                //LDS lds = null;//passportService.getLDS();
                List<Short> fileList = psLDS.getFileList();
                Collections.sort(fileList);

                for (short fid : fileList) {
                    switch (fid) {
                        case PassportService.EF_COM:
                            COMFile comFile = psLDS.getCOMFile();
                            Log.i(TAG, "comFile=" + comFile.toString());
                            break;
                        case PassportService.EF_SOD:
                            SODFile sodFile = psLDS.getSODFile();

                            X500Principal principal = sodFile.getIssuerX500Principal();
                            String digestAlgorithm = sodFile.getDigestAlgorithm();
                            String digestEncryptionAlgorithm = sodFile.getDigestEncryptionAlgorithm();
                            byte[] encryptedDigest = sodFile.getEncryptedDigest();
                            if (principal != null) {

                                String name = principal.getName(X500Principal.RFC1779);

                                X509Certificate certificate = null;
                                try {
                                    certificate = sodFile.getDocSigningCertificate();

                                    PublicKey pkey = certificate.getPublicKey();
                                    BigInteger big = new BigInteger(pkey.getEncoded());
                                    Log.i(TAG, "crypto DATAGROUP DIGEST ALGORITHM: " + sodFile.getDigestAlgorithm());

                                } catch (CertificateException ce) {
                                    Log.e(TAG, "handleFileInterpreted >> CertificateException");
                                    ce.printStackTrace();
                                }

                                Log.i(TAG, ">> issuer = " + name);
                                Log.i(TAG, ">> certificate = " + certificate);
                                Log.i(TAG, ">> digestAlgorithm = " + digestAlgorithm);
                                Log.i(TAG, ">> digestEncryptionAlgorithm = " + digestEncryptionAlgorithm);
                                Log.i(TAG, ">> encryptedDigest = " + encryptedDigest);
                            }
                            break;
                        case PassportService.EF_DG1:
                            DG1File dg1File = psLDS.getDG1File();

                            Log.d(TAG, ">> EF_DG1_TAG");
                            MRZInfo mrzInfo = dg1File.getMRZInfo();
                            /*documentNumberW.setText(mrzInfo.getDocumentNumber());
                            personalNumberW.setText(mrzInfo.getPersonalNumber());
                            issuingStateW.setText(mrzInfo.getIssuingState());
                            primaryIdentifierW.setText(mrzInfo.getPrimaryIdentifier().replace("<", " ").trim());
                            secondaryIdentifiersW.setText(mrzInfo.getSecondaryIdentifier().replace("<", " ").trim());
                            genderW.setText(mrzInfo.getGender().toString());
                            nationalityW.setText(mrzInfo.getNationality());
                            dobW.setText(Utils.mrzDate2visualDate(mrzInfo.getDateOfBirth()));
                            doeW.setText(Utils.mrzDate2visualDate(mrzInfo.getDateOfExpiry()));*/
                            mrzDG1 = mrzInfo.toString();
                            Log.i(TAG, ">> MRZ >>" + mrzInfo);
                            break;
                        case PassportService.EF_DG2:
                            DG2File dg2File = psLDS.getDG2File();

                            List<FaceInfo> faceInfos = dg2File.getFaceInfos();
                            for (FaceInfo faceInfo : faceInfos) {
                                allFaceImageInfos.addAll(faceInfo.getFaceImageInfos());
                            }


                            break;
                        /*
                        case PassportService.EF_DG5:
                            DG5File dg5File = psLDS.getDG5File();
                            break;
                        case PassportService.EF_DG6:
                            DG6File dg6File = psLDS.getDG6File();
                            break;
                        case PassportService.EF_DG7:
                            DG7File dg7File = psLDS.getDG7File();
                            break;
                            */
                        case PassportService.EF_DG14:

//                            try {
//                                DG14File dg14File = psLDS.getDG14File();
//
//                                PrivateKey terminalKey = null;
//                                List<CardVerifiableCertificate> cvCertificates = null;
//                                Map<BigInteger, PublicKey> publicKeyMap = dg14File.getChipAuthenticationPublicKeyInfos();
//                                BigInteger cardPublicKeyId = BigInteger.valueOf(-1);
//                                List<Short> cvcaFIDs = dg14File.getCVCAFileIds();
//                                Log.i(TAG, "cvcaFIDs=" + cvcaFIDs);
//
//                                Log.i(TAG, "publicKeyMap=" + publicKeyMap);
//                                Log.i(TAG, "terminalKey=" + terminalKey);
//                                Log.i(TAG, "cvCertificates=" + cvCertificates);
//                                Log.i(TAG, "cardPublicKeyId=" + cardPublicKeyId);
//                            } catch (Exception e) {
//                                e.printStackTrace();
//                            }


                            break;
                        case PassportService.EF_DG15:
                            DG15File dg15File = psLDS.getDG15File();
                            PublicKey mDG15_PK = dg15File.getPublicKey();
                            Log.i(TAG, "dg15 Public Key=" + mDG15_PK);
                            break;
//                        case PassportService.EF_CVCA:
//                            CVCAFile cvcaFile = psLDS.getCVCAFile();
//                            CVCPrincipal altCARef = cvcaFile.getAltCAReference();
//                            CVCPrincipal caRef = cvcaFile.getCAReference();
//                            Log.i(TAG, "altCARef>> Mnemonic=" + altCARef.getMnemonic() + "; name=" + altCARef.getName() + "; SeqNumber=" + altCARef.getSeqNumber() + "; country=" + altCARef.getCountry());
//                            Log.i(TAG, "caRef>> Mnemonic=" + caRef.getMnemonic() + "; name=" + caRef.getName() + "; SeqNumber=" + caRef.getSeqNumber() + "; country=" + caRef.getCountry());
//
//                            break;
                        /*case PassportService.EF_DG3:
                            Logging.d(TAG+ "AsyncPassportInterpret::PassportService.EF_DG3");
                            publishProgress(new PassportProgress(PassportProgress.STARTED, LDSFile.EF_DG3_TAG));
                            DG3File dg3File = lds.getDG3File();
                            publishProgress(new PassportProgress(PassportProgress.FINISHED, dg3File));
                            break;*/


                        default:
                        /* All other files are ignored. */
                            break;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "AsyncPassportInterpret: EXCEPTION: " + e.getMessage());
                e.printStackTrace();
            }
            return null;
        }

        @Override
        protected void onPostExecute(Void v) {
            //			isDisplaying = false;
            //			imageProgressBar.setVisibility(ProgressBar.INVISIBLE);
            Log.i(TAG, ">>>> AsyncPassportInterpret >> onPostExecute");
            if (allFaceImageInfos.size() > 0) {
                new AsyncImageDecode().execute(allFaceImageInfos.get(0));
                dg1TextView.setText(mrzDG1);
            }
            /*VerificationStatus verificationStatus = passport.verifySecurity();
            if (verificationStatus.getBAC() == VerificationStatus.Verdict.SUCCEEDED) {
                flagBAC.setTextColor(Color.parseColor("#00ccff"));
            } else if (verificationStatus.getBAC() == VerificationStatus.Verdict.FAILED) {
                flagBAC.setTextColor(Color.parseColor("#FF4081"));
            } else {
                flagBAC.setTextColor(Color.parseColor("#ffcccccc"));
            }*/

            //Logging.i(TAG + ">>>> verificationStatus >> BAC : " + verificationStatus.getBACReason().toString());
            //Logging.i(TAG + ">>>> verificationStatus >> AA : " + verificationStatus.getAAReason().toString());
            //Logging.i(TAG + ">>>> verificationStatus >> CS : " + verificationStatus.getCSReason().toString());
            //Logging.i(TAG + ">>>> verificationStatus >> DS : " + verificationStatus.getDSReason().toString());
            //Logging.i(TAG + ">>>> verificationStatus >> HT : " + verificationStatus.getHTReason().toString());
            try {
                //Logging.i(TAG + ">>>> verificationStatus >> EAC : " + verificationStatus.getEACReason().toString());
            } catch (Exception e) {

            }
        }
    }

    class AsyncImageDecode extends AsyncTask<FaceImageInfo, ImageProgress, Bitmap> {

        @Override
        protected Bitmap doInBackground(FaceImageInfo... params) {
            try {
                FaceImageInfo faceImageInfo = params[0];
                final int imageLength = faceImageInfo.getImageLength();
                String mimeType = faceImageInfo.getMimeType();
                InputStream faceImageInputStream = faceImageInfo.getImageInputStream();
                DataInputStream dataInputStream = new DataInputStream(faceImageInputStream);
                byte[] bytesIn = new byte[(int) imageLength];
                int count = 0;
                Bitmap bitmap = null;
                ImageProgress progress = new ImageProgress(0, imageLength, null);
                for (int percentage = 9; percentage <= 100; percentage += 7) {
                    int newCount = (int) (percentage * imageLength / 100);
                    try {
                        dataInputStream.readFully(bytesIn, count, newCount - count);
                        count = newCount;
                        InputStream inputStream = new ByteArrayInputStream(bytesIn, 0, count);
                        // Logging.v(TAG+ "calling ImageUtil.read(inputStream, " + count + ", \"" + mimeType + "\"");
                        ImageUtil imageUtil = new ImageUtil();
                        bitmap = imageUtil.read(inputStream, count, mimeType);
                        progress.setOffset(count);
                        progress.setBitmap(bitmap);
                        Log.d("AsyncImageDecode", "decode image " + progress);
                        publishProgress(progress);
                    } catch (Throwable e) {
                        //Logging.e(TAG+ "AsyncImageDecode >> ignoring exception");
                    }
                }


                return bitmap;
            } catch (Exception e) {
                Log.e("AsyncImageDecode", "AsyncImageDecode" + e.getMessage());
                //e.printStackTrace();
                return null;
            }
        }

        /*
                @Override
                protected void onProgressUpdate(ImageProgress... progress) {
                    int offset = progress[0].getOffset();
                    int length = progress[0].getLength();
                    Bitmap bitmap = progress[0].getBitmap();
                    if (bitmap != null && length != 0) {
                        imageView.setBackgroundDrawable(new BitmapDrawable(bitmap));
                    }
                }
        */
        @Override
        protected void onPostExecute(Bitmap bitmap) {
            try {
                dg2ImageView.setBackgroundDrawable(null);
                dg2ImageView.setImageBitmap(bitmap);

                byte[] array = compress2JpegByte(bitmap, 100);
                String imageDG2 = convertStream2base64(array);

                //imageProgressBar.setVisibility(ProgressBar.INVISIBLE);
                dg2ImageView.setVisibility(ImageView.VISIBLE);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    class ImageProgress {

        private int offset;
        private int length;
        private Bitmap bitmap;

        public ImageProgress(int offset, int length, Bitmap bitmap) {
            this.offset = offset;
            this.length = length;
            this.bitmap = bitmap;
        }

        public int getOffset() {
            return offset;
        }

        public void setOffset(int offset) {
            this.offset = offset;
        }

        public int getLength() {
            return length;
        }

        public void setLength(int length) {
            this.length = length;
        }

        public Bitmap getBitmap() {
            return bitmap;
        }

        public void setBitmap(Bitmap bitmap) {
            this.bitmap = bitmap;
        }

        public String toString() {
            return "[ImageProgress: "
                    + "offset: " + offset
                    + ", length: " + length
                    + ", bitmap: " + (bitmap == null ? "null" : bitmap.getWidth() + "x" + bitmap.getHeight())
                    + "]";
        }
    }

    public static byte[] compress2JpegByte(Bitmap src, int quality) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        src.compress(Bitmap.CompressFormat.JPEG, quality, os);

        byte[] array = os.toByteArray();
        return array;
    }

    public static String convertStream2base64(byte[] bufferImg) {
        return (Base64.encodeToString(bufferImg, 0, bufferImg.length, Base64.DEFAULT));
    }

    /**
     * Copy pasted, because original uses explicit cast to BouncyCastle key implementation, whereas we have a spongycastle one
     */
    public synchronized ChipAuthenticationResult doCA(PassportService ps, BigInteger keyId, PublicKey publicKey) throws CardServiceException {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key is null");
        }
        try {
            String agreementAlg = Util.inferKeyAgreementAlgorithm(publicKey);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(agreementAlg);
            AlgorithmParameterSpec params = null;
            if ("DH".equals(agreementAlg)) {
                DHPublicKey dhPublicKey = (DHPublicKey) publicKey;
                params = dhPublicKey.getParams();
            } else if ("ECDH".equals(agreementAlg)) {
                ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                params = ecPublicKey.getParams();
            } else {
                throw new IllegalStateException("Unsupported algorithm \"" + agreementAlg + "\"");
            }
            keyPairGenerator.initialize(params);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            KeyAgreement agreement = KeyAgreement.getInstance(agreementAlg);
            agreement.init(keyPair.getPrivate());
            agreement.doPhase(publicKey, true);

            byte[] secret = agreement.generateSecret();

            // TODO: this SHA1ing may have to be removed?
            // TODO: this hashing is needed for our Java Card passport applet implementation
            // byte[] secret = md.digest(secret);

            byte[] keyData = null;
            byte[] idData = null;
            byte[] keyHash = new byte[0];
            if ("DH".equals(agreementAlg)) {
                DHPublicKey dhPublicKey = (DHPublicKey) keyPair.getPublic();
                keyData = dhPublicKey.getY().toByteArray();
                // TODO: this is probably wrong, what should be hashed?
                MessageDigest md = MessageDigest.getInstance("SHA1");
                md = MessageDigest.getInstance("SHA1");
                keyHash = md.digest(keyData);
            } else if ("ECDH".equals(agreementAlg)) {
                org.spongycastle.jce.interfaces.ECPublicKey ecPublicKey = (org.spongycastle.jce.interfaces.ECPublicKey) keyPair.getPublic();
                keyData = ecPublicKey.getQ().getEncoded();
                byte[] t = Util.i2os(ecPublicKey.getQ().getX().toBigInteger());
                keyHash = Util.alignKeyDataToSize(t, ecPublicKey.getParameters().getCurve().getFieldSize() / 8);
            }
            keyData = Util.wrapDO((byte) 0x91, keyData);
            if (keyId.compareTo(BigInteger.ZERO) >= 0) {
                byte[] keyIdBytes = keyId.toByteArray();
                idData = Util.wrapDO((byte) 0x84, keyIdBytes);
            }
            ps.sendMSEKAT(ps.getWrapper(), keyData, idData);

            SecretKey ksEnc = Util.deriveKey(secret, Util.ENC_MODE);
            SecretKey ksMac = Util.deriveKey(secret, Util.MAC_MODE);

            ps.setWrapper(new DESedeSecureMessagingWrapper(ksEnc, ksMac, 0L));
            Field fld = PassportService.class.getDeclaredField("state");
            fld.setAccessible(true);
            fld.set(ps, 4); //PassportService.CA_AUTHENTICATED_STATE)
            return new ChipAuthenticationResult(keyId, publicKey, keyHash, keyPair);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CardServiceException(e.toString());
        }
    }


    public synchronized TerminalAuthenticationResult doTA(PassportService ps, CVCPrincipal caReference, List<CardVerifiableCertificate> terminalCertificates,
                                                          PrivateKey terminalKey, String taAlg, ChipAuthenticationResult chipAuthenticationResult, String documentNumber) throws CardServiceException {
        try {
            if (terminalCertificates == null || terminalCertificates.size() < 1) {
                throw new IllegalArgumentException("Need at least 1 certificate to perform TA, found: " + terminalCertificates);
            }

            byte[] caKeyHash = chipAuthenticationResult.getKeyHash();
            /* The key hash that resulted from CA. */
            if (caKeyHash == null) {
                throw new IllegalArgumentException("CA key hash is null");
            }

			/* FIXME: check that terminalCertificates holds a (inverted, i.e. issuer before subject) chain. */

			/* Check if first cert is/has the expected CVCA, and remove it from chain if it is the CVCA. */
            CardVerifiableCertificate firstCert = terminalCertificates.get(0);
            CVCAuthorizationTemplate.Role firstCertRole = firstCert.getAuthorizationTemplate().getRole();
            if (CVCAuthorizationTemplate.Role.CVCA.equals(firstCertRole)) {
                CVCPrincipal firstCertHolderReference = firstCert.getHolderReference();
                if (caReference != null && !caReference.equals(firstCertHolderReference)) {
                    throw new CardServiceException("First certificate holds wrong authority, found " + firstCertHolderReference.getName() + ", expected " + caReference.getName());
                }
                if (caReference == null) {
                    caReference = firstCertHolderReference;
                }
                terminalCertificates.remove(0);
            }
            CVCPrincipal firstCertAuthorityReference = firstCert.getAuthorityReference();
            if (caReference != null && !caReference.equals(firstCertAuthorityReference)) {
                throw new CardServiceException("First certificate not signed by expected CA, found " + firstCertAuthorityReference.getName() + ",  expected " + caReference.getName());
            }
            if (caReference == null) {
                caReference = firstCertAuthorityReference;
            }

			/* Check if the last cert is an IS cert. */
            CardVerifiableCertificate lastCert = terminalCertificates.get(terminalCertificates.size() - 1);
            CVCAuthorizationTemplate.Role lastCertRole = lastCert.getAuthorizationTemplate().getRole();
            if (!CVCAuthorizationTemplate.Role.IS.equals(lastCertRole)) {
                throw new CardServiceException("Last certificate in chain (" + lastCert.getHolderReference().getName() + ") does not have role IS, but has role " + lastCertRole);
            }
            CardVerifiableCertificate terminalCert = lastCert;

            int i = 0;
            /* Have the MRTD check our chain. */
            for (CardVerifiableCertificate cert : terminalCertificates) {
                try {
                    CVCPrincipal authorityReference = cert.getAuthorityReference();

					/* Step 1: MSE:SetDST */
                    /* Manage Security Environment: Set for verification: Digital Signature Template,
                     * indicate authority of cert to check.
					 */
                    byte[] authorityRefBytes = Util.wrapDO((byte) 0x83, authorityReference.getName().getBytes("ISO-8859-1"));
                    ps.sendMSESetDST(ps.getWrapper(), authorityRefBytes);

					/* Cert body is already in TLV format. */
                    byte[] body = cert.getCertBodyData();

					/* Signature not yet in TLV format, prefix it with tag and length. */
                    byte[] signature = cert.getSignature();
                    ByteArrayOutputStream sigOut = new ByteArrayOutputStream();
                    TLVOutputStream tlvSigOut = new TLVOutputStream(sigOut);
                    tlvSigOut.writeTag(0x5F37); //TAG_CVCERTIFICATE_SIGNATURE);
                    tlvSigOut.writeValue(signature);
                    tlvSigOut.close();
                    signature = sigOut.toByteArray();

					/* Step 2: PSO:Verify Certificate */
                    ps.sendPSOChainMode(ps.getWrapper(), body, signature);
                } catch (Exception cse) {
                    Log.w("FOO", String.valueOf(i));
                    throw cse;
                }
                i++;
            }

            if (terminalKey == null) {
                throw new CardServiceException("No terminal key");
            }

			/* Step 3: MSE Set AT */
            CVCPrincipal holderRef = terminalCert.getHolderReference();
            byte[] holderRefBytes = Util.wrapDO((byte) 0x83, holderRef.getName().getBytes("ISO-8859-1"));
            /* Manage Security Environment: Set for external authentication: Authentication Template */
            ps.sendMSESetATExtAuth(ps.getWrapper(), holderRefBytes);

			/* Step 4: send get challenge */
            byte[] rPICC = ps.sendGetChallenge(ps.getWrapper());

			/* Step 5: external authenticate. */
            /* FIXME: idPICC should be public key in case of PACE. See BSI TR 03110 v2.03 4.4. */
            byte[] idPICC = new byte[documentNumber.length() + 1];
            System.arraycopy(documentNumber.getBytes("ISO-8859-1"), 0, idPICC, 0, documentNumber.length());
            idPICC[idPICC.length - 1] = (byte) MRZInfo.checkDigit(documentNumber);

            ByteArrayOutputStream dtbs = new ByteArrayOutputStream();
            dtbs.write(idPICC);
            dtbs.write(rPICC);
            dtbs.write(caKeyHash);
            dtbs.close();
            byte[] dtbsBytes = dtbs.toByteArray();

            String sigAlg = terminalCert.getSigAlgName();
            if (sigAlg == null) {
                throw new IllegalStateException("ERROR: Could not determine signature algorithm for terminal certificate " + terminalCert.getHolderReference().getName());
            }
            Signature sig = Signature.getInstance(sigAlg);
            sig.initSign(terminalKey);
            sig.update(dtbsBytes);
            byte[] signedData = sig.sign();
            if (sigAlg.toUpperCase().endsWith("ECDSA")) {
                int keySize = ((org.bouncycastle.jce.interfaces.ECPrivateKey) terminalKey).getParameters().getCurve().getFieldSize() / 8;
                signedData = Util.getRawECDSASignature(signedData, keySize);
            }
            ps.sendMutualAuthenticate(ps.getWrapper(), signedData);
            Field fld = PassportService.class.getDeclaredField("state");
            fld.setAccessible(true);
            fld.set(ps, 5); //PassportService.TA_AUTHENTICATED_STATE)
            return new TerminalAuthenticationResult(chipAuthenticationResult, caReference, terminalCertificates, terminalKey, documentNumber, rPICC);
        } catch (CardServiceException cse) {
            throw cse;
        } catch (Exception e) {
            throw new CardServiceException(e.toString());
        }
    }

}
