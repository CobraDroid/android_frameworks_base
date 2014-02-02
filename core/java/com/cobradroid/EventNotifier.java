/*
 * com/cobradroid/EventNotifier.java - Class to record suspicious events
 * Copyright (c) 2014 Jake Valletta
 *
 *
 * Author:
 * Jake Valletta     -javallet@gmail.com, @jake_valletta
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.cobradroid;

import android.net.Uri;
import android.util.Seclog;
import android.text.TextUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

public class EventNotifier {

    private static final String EVENT_CONTENT_PROVIDER = "ContentProviderQuery";
    private static final String UNKNOWN = "unknown";

    private static String getProcessName() {
        
        File file = new File("/proc/self/cmdline");
        BufferedReader br;

        try {
            br = new BufferedReader(new FileReader(file));
            String line;

            if ((line = br.readLine()) != null) {
                return line.replaceAll("[^\\x01-\\x7F]", "");
            }
            else {
                return UNKNOWN;
            }

        } catch (FileNotFoundException e) {
            return UNKNOWN;
        } catch (IOException e) {
           return UNKNOWN;
        }
    }
    /* Record access to a content provider */
    public static void recordContentProvider(Uri url, String[] projection, String selection,
            String[] selectionArgs) {

        String urlString = url.toString();
        String projectionString = projection == null ? "()" : "("+TextUtils.join(",", projection)+")";
        String selectionString =  selection == null ? "()" : selection;    
        String calleeApplication = getProcessName();

        Seclog.d(EVENT_CONTENT_PROVIDER, "["+calleeApplication+"] Database access: \""+urlString+
             "\" "+projectionString+" "+selectionString);

    }
}
