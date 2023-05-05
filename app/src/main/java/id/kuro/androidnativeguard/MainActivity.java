package id.kuro.androidnativeguard;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.text.Html;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    TextView tv_main;

    public native String getResult();
    static {
        System.loadLibrary("NativeGuard");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tv_main = findViewById(R.id.tv_main);
        tv_main.setText(Html.fromHtml(getResult()));
    }
}