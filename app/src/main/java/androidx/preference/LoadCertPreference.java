// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package androidx.preference;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;

import android.text.ClipboardManager;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Base64;
import android.widget.EditText;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import com.ubergeek42.WeechatAndroid.R;
import com.ubergeek42.WeechatAndroid.utils.Utils;
import com.ubergeek42.cats.Kitty;
import com.ubergeek42.cats.Root;

import java.io.IOException;

public class LoadCertPreference extends DialogPreference {
    final private static @Root Kitty kitty = Kitty.make();
    final private static String password = "p12 password";

    public LoadCertPreference(Context context, AttributeSet attrs) {
        super(context, attrs);
    }

    @Override public CharSequence getSummary() {
        final String set_not_set = getContext().getString(getPersistedLong(0) == 0 ? R.string.pref_file_not_set : R.string.pref_file_set);
        return getContext().getString(R.string.pref_file_summary,
                super.getSummary(), set_not_set);
    }

    private boolean saveData(@Nullable byte[] bytes) {
        if (callChangeListener(bytes)) {
            if (bytes == null) {
                persistLong(0);
                return true;
            } else {
                try {
                    KeyStore clientKeystore = KeyStore.getInstance("PKCS12");
                    clientKeystore.load(new ByteArrayInputStream(bytes), password.toCharArray());

                    KeyStore androidKeystore = KeyStore.getInstance("AndroidKeyStore");
                    androidKeystore.load(null);

                    Enumeration<String> aliases = androidKeystore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        kitty.error("alias " + alias);
                        if (alias.startsWith("client.")) {
                            androidKeystore.deleteEntry(alias);
                        }
                    }

                    aliases = clientKeystore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        kitty.error("file alias " + alias);
                        if (clientKeystore.isCertificateEntry(alias)) {
                            kitty.error("file cert alias " + alias);
                            // these are server certs, which aren't currently passed to the trust store
                            Certificate cert = clientKeystore.getCertificate(alias);
                            androidKeystore.setCertificateEntry("client." + alias, cert);
                        } else if (clientKeystore.isKeyEntry(alias)) {
                            kitty.error("file key alias " + alias);
                            Key key = clientKeystore.getKey(alias, password.toCharArray());
                            Certificate[] certs = clientKeystore.getCertificateChain(alias);
                            androidKeystore.setKeyEntry("client." + alias, key, new char[0], certs);
                        }
                    }

                    persistLong(System.nanoTime());
                    notifyChanged();
                    return true;
                } catch (KeyStoreException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | CertificateException e) {
                    Toast.makeText(getContext(), getContext().getString(R.string.pref_file_error, e.getMessage()), Toast.LENGTH_SHORT).show();
                    kitty.error("saveData()", e);
                }
            }
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    // this gets called when a file has been picked
    public void onActivityResult(@NonNull Intent intent) {
        try {
            if (saveData(Utils.readFromUri(getContext(), intent.getData()))) {
                Toast.makeText(getContext(), getContext().getString(R.string.pref_file_imported), Toast.LENGTH_SHORT).show();
            }
        } catch (IOException e) {
            Toast.makeText(getContext(), getContext().getString(R.string.pref_file_error, e.getMessage()), Toast.LENGTH_SHORT).show();
            kitty.error("onActivityResult()", e);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////

    public static class LoadCertPreferenceFragment extends PreferenceDialogFragmentCompat {

        public static LoadCertPreferenceFragment newInstance(String key, int code) {
            LoadCertPreferenceFragment fragment = new LoadCertPreferenceFragment();
            Bundle b = new Bundle(1);
            b.putString("key", key);
            b.putInt("code", code);
            fragment.setArguments(b);
            return fragment;
        }

        @Override protected void onPrepareDialogBuilder(AlertDialog.Builder builder) {
            builder.setNeutralButton(getString(R.string.pref_file_clear_button), (dialog, which) -> {
                ((LoadCertPreference) getPreference()).saveData(null);
                Toast.makeText(getContext(), getString(R.string.pref_file_cleared), Toast.LENGTH_SHORT).show();
            })
                .setNegativeButton(getString(R.string.pref_file_paste_button), (dialog, which) -> {
                    // noinspection deprecation
                    ClipboardManager cm = (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
                    CharSequence clip = cm.getText();
                    if (TextUtils.isEmpty(clip))
                        Toast.makeText(getContext(), getString(R.string.pref_file_empty_clipboard), Toast.LENGTH_SHORT).show();
                    else {
                        if (((LoadCertPreference) getPreference()).saveData(clip.toString().getBytes())) {
                            Toast.makeText(getContext(), getString(R.string.pref_file_pasted), Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .setPositiveButton(getString(R.string.pref_file_choose_button), (dialog, which) -> {
                    Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                    intent.setType("*/*");
                    //noinspection ConstantConditions   -- both target fragment and arguments are set
                    getTargetFragment().startActivityForResult(intent, getArguments().getInt("code"));
                });
        }

        @Override public void onDialogClosed(boolean b) {}
    }
}
