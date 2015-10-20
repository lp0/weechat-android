/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.ubergeek42.WeechatAndroid.relay;

public interface BufferEye {

    void onLinesChanged();

    void onLinesListed();

    void onPropertiesChanged();

    void onBufferClosed();
}
