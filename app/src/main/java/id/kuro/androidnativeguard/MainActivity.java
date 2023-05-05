package id.kuro.androidnativeguard;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.text.Html;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    static TextView tv_main;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tv_main = findViewById(R.id.tv_main);
        System.loadLibrary("NativeGuard");
    }

    public static void addLog(String log) {
        tv_main.append(Html.fromHtml(log + "<br>"));
    }
}