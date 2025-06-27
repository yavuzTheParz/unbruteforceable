
function convert_upper_to_lower()
    % Read the content of the input file
    fid = fopen("english-quadgrams.txt", 'r');
    if fid == -1
        error('Cannot open input file: %s', "henrySpeech.txt");
    end
    text = fread(fid, '*char')';
    fclose(fid);

    % Convert all uppercase letters to lowercase
    convertedText = lower(text);

    % Write the result to the output file
    fid = fopen("english-quadgrams.txt", 'w');
    if fid == -1
        error('Cannot open output file: %s', "triagrams.txt");
    end
    fwrite(fid, convertedText);
    fclose(fid);

    fprintf('Conversion complete. Result written');
end
