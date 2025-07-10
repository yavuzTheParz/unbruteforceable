function key = decrypt_Vigenere(keyLength)

    T = 500;
    N = 800;
    crossOver_p = 0.9;
    pop = initialize(keyLength, N);
    startTime = tic;       

    mutuation_p = 0.05;
    fid = fopen("encryptedHenrySpeech.txt", 'r');
    cipherText = fread(fid, '*char')';  % read whole file as char row vector
    fclose(fid);
    
    data = load("quadgram_probs.mat");
    quadgram_probs = data.quadgram_probs;
    
    stagnation_counter = 0;
    prev_key = pop(1).key;

    diagnose_every = floor(T * 0.2);
    focus_mask = true(1, keyLength);  % initially, mutate all

    
    pop = evaluate(pop, cipherText, quadgram_probs);
    
    for i = 1:T

        if mod(i, diagnose_every) == 0
            focus_mask = diagnose_key(pop(1).key, cipherText, quadgram_probs);
        end
        
        matingPool = selection(pop);
        offspring = variation(matingPool, crossOver_p, mutuation_p, focus_mask);
        offspring = evaluate(offspring, cipherText, quadgram_probs);
        pop = survival(offspring, pop);
        
        fprintf('current key is: %s\n', pop(1).key);
        recalculate = (pop(1).fitness) * (17 - 3 + 1);
        fprintf('fitness of the current key is: %.5f\n', recalculate);
        fprintf('Generation: %d and ', i);
        elapsedTime = toc(startTime);
        fprintf('time: %.2f\n', elapsedTime);
        
        if strcmp(pop(1).key, prev_key)
            stagnation_counter = stagnation_counter + 1;
        else
            stagnation_counter = 0;
            prev_key = pop(1).key;

        end

        if stagnation_counter >= 100
            fprintf('\n[Stagnation detected – Reinitializing population using elite and focus mask...]\n');
            [~, sortedIdx] = sort([pop.fitness], 'descend');
            elite = pop(sortedIdx(1));
            top_individuals = pop(sortedIdx(2:4));
            pop = reinitialize_population_from_elite(elite, focus_mask, N, top_individuals,crossOver_p);
            pop = evaluate(pop, cipherText, quadgram_probs);
            stagnation_counter = 0;
            focus_mask = diagnose_key(pop(1).key, cipherText, quadgram_probs);
        end

    end
    
    key = pop(1).key;
    time = elapsedTime;
    
    fprintf('Key cracked in %.2f seconds\n', elapsedTime);
    fprintf('The key is: %s\n', pop(1).key);
    fprintf('decrypted text is: %s\n', decrypt(cipherText, pop(1).key));
end


%%
function pop = initialize(keyLength, N)
    pop(N) = struct('key', '', 'fitness', 0);
    for i = 1:N
        pop(i).key = char(randi([32, 127], 1, keyLength));
        pop(i).fitness = 0;
    end
end
%%
function matingPool = selection(pop)
    N = numel(pop);
    matingPool = pop;

    % Sort population by descending fitness
    [~, sortedIdx] = sort([pop.fitness], 'descend');
    rankedPop = pop(sortedIdx);

    % Linear ranking selection
    s = 1.5;  % selection pressure: 1 ≤ s ≤ 2 (higher means stronger pressure)
    probs = zeros(1, N);
    for i = 1:N
        probs(i) = (2 - s)/N + (2 * (i - 1) * (s - 1)) / (N * (N - 1));
    end

    % Cumulative probability for roulette-wheel selection
    cum_probs = cumsum(probs);

    % Selection
    for i = 1:N
        r = rand();
        idx = find(cum_probs >= r, 1, 'first');
        matingPool(i) = rankedPop(idx);
    end
end
%%
function offspring = variation(matingPool, cross_over_p, mutation_p, focus_mask)
    N = numel(matingPool);
    offspring = matingPool;
    for i = 1:N
        nums = randperm(N, 2);
        pair1 = matingPool(nums(1));
        pair2 = matingPool(nums(2));

        if cross_over_p > rand()
            child = crossOver(pair1, pair2, focus_mask,cross_over_p);
        else
            child = matingPool(i);
        end
        offspring(i) = mutation(child, mutation_p, focus_mask);
    end
end
%%
function child = crossOver(pair1, pair2, focus_mask, cross_over_p)
    keyLength = length(pair1.key);
    k = 2;  % number of crossover points (can be increased)

    points = sort(randperm(keyLength - 1, k));
    points = [0, points, keyLength];

    child = pair1;  % keep full struct (key + fitness)

    swap = false;
    for seg = 1:length(points) - 1
        start_idx = points(seg) + 1;
        end_idx = points(seg + 1);
        if rand() < cross_over_p
            swap = ~swap;
        end
        for i = start_idx:end_idx
            if focus_mask(i) && swap
                child.key(i) = pair2.key(i);
            end
        end
    end
end
%%

function mutated = mutation(original, mutation_p, focus_mask)
    mutated = original;
    for i = 1:length(original.key)
        if focus_mask(i)
            if rand() < mutation_p  % boost mutation at likely-wrong spots
                mutated.key(i) = char(randi([32, 127]));
            end
        end

    end
end

%%
function offspring = evaluate(offspring, cipherText, quadgram_probs)
    asciiText = regexprep(cipherText, '[^ -~]', '');
    n = 4;
    penalty = log10(1e-8);
    for o = 1:numel(offspring)
        plaintext = decrypt(asciiText, offspring(o).key);
        lettersOnly = lower(regexprep(plaintext, '[^a-z]', ''));
        L = length(lettersOnly);
        if L < n
            offspring(o).fitness = penalty * 10;
            continue;
        end
        log_prob_sum = 0;
        for i = 1:L - n + 1
            quad = lettersOnly(i : i + n - 1);
            if isfield(quadgram_probs, quad)
                p = quadgram_probs.(quad);
                if p > 0
                    log_prob_sum = log_prob_sum + log10(p);
                else
                    log_prob_sum = log_prob_sum + penalty;
                end
            else
                log_prob_sum = log_prob_sum + penalty;
            end
        end
        offspring(o).fitness = log_prob_sum / (L - n + 1);
    end
end


%%
function plaintext = decrypt(cipherText, key)
    ascii_min = 32;
    ascii_max = 126;
    range = ascii_max - ascii_min + 1;
    cipherNums = double(cipherText);
    keyNums = double(key);
    keyLength = length(keyNums);
    textLength = length(cipherNums);
    plainNums = zeros(1, textLength);
    for i = 1:textLength
        keyIndex = mod(i - 1, keyLength) + 1;
        plainNums(i) = mod(cipherNums(i) - keyNums(keyIndex), range);
        if plainNums(i) < 0
            plainNums(i) = plainNums(i) + range;
        end
        plainNums(i) = plainNums(i) + ascii_min;
    end
    plaintext = char(plainNums);
end


%%
function pop = survival(offspring, pop)
    N = numel(pop);
    merged = [pop, offspring];
    [~, sortedIndices] = sort([merged.fitness], 'descend');
    bestIndividual = merged(sortedIndices(1));
    pop = merged(sortedIndices(1:N));
    if ~any(arrayfun(@(x) strcmp(x.key, bestIndividual.key), pop))
        pop(end) = bestIndividual;
    end
end
%%

function fitness = evaluate_key(candidate, cipherText, quadgram_probs)
    asciiText = regexprep(cipherText, '[^ -~]', '');
    n = 4;
    penalty = log10(1e-8);
    plaintext = decrypt(asciiText, candidate);
    lettersOnly = lower(regexprep(plaintext, '[^a-z]', ''));
    L = length(lettersOnly);
    log_prob_sum = 0;
    for i = 1:L - n + 1
        quad = lettersOnly(i : i + n - 1);
        if isfield(quadgram_probs, quad)
            p = quadgram_probs.(quad);
            if p > 0
                log_prob_sum = log_prob_sum + log10(p);
            else
                log_prob_sum = log_prob_sum + penalty;
            end
        else
            log_prob_sum = log_prob_sum + penalty;
        end
    end
    fitness = log_prob_sum / (L - n + 1);
end
%%
function [likely_wrong_mask] = diagnose_key(key, cipherText, quadgram_probs)
    fprintf('\n[Diagnosis phase triggered]\n');
    keyLength = length(key);
    originalFitness = evaluate_key(key, cipherText, quadgram_probs);
    ascii_min = 32; ascii_max = 126;
    ascii_range = ascii_max - ascii_min + 1;

    threshold = 0.1;
    num_reps = 6;
    num_random = 6;
    total_tests = num_reps + num_random;

    likely_wrong_mask = false(1, keyLength);

    for i = 1:keyLength
        worse_count = 0;
        original_char = key(i);

        tested_chars = char([]);

        % Add representative characters
        for f = linspace(0.1, 0.9, num_reps)
            c = char(round(ascii_min + ascii_range * f));
            if c ~= original_char
                tested_chars(end + 1) = c;
            end
        end

        while numel(tested_chars) < total_tests
            rnd = char(randi([ascii_min, ascii_max]));
            if ~ismember(rnd, [tested_chars, original_char])
                tested_chars(end + 1) = rnd;
            end
        end

        % Evaluate substitutions
        for testChar = tested_chars
            testKey = key;
            testKey(i) = testChar;
            %fprintf('Testing the key: %s\n', testKey);
            newFitness = evaluate_key(testKey, cipherText, quadgram_probs);
            if newFitness > originalFitness - threshold
                worse_count = worse_count + 1;
            end
        end
        %fprintf('===================================\n');

        if worse_count >= 1
            likely_wrong_mask(i) = true;
        end
    end

    fprintf('Likely wrong positions: %s\n', mat2str(find(likely_wrong_mask)));
end
%%
function pop = reinitialize_population_from_elite(elite, focus_mask, N, top_individuals, crossOver_p)
    % elite: best individual (struct with .key and .fitness)
    % focus_mask: logical array indicating positions to vary
    % N: population size
    % top_individuals: array of top-K individuals for crossover

    ascii_min = 32;
    ascii_max = 126;
    keyLength = length(elite.key);

    % Initialize population structure
    pop(N) = struct('key', '', 'fitness', 0);
    
    % Keep elite
    pop(1) = elite;

    K = numel(top_individuals);  % typically 3–5 best individuals

    for i = 2:N
        newKey = elite.key;

        if rand() < crossOver_p && K > 1
            % Hybridize with another top individual via crossover
            mate = top_individuals(randi(K)).key;
            for j = 1:keyLength
                if focus_mask(j)
                    newKey(j) = mate(j);
                end
            end
        else
            % Randomize only wrong positions
            for j = 1:keyLength
                if focus_mask(j)
                    newKey(j) = char(randi([ascii_min, ascii_max]));
                end
            end
        end

        pop(i).key = newKey;
        pop(i).fitness = 0;
    end
end

%[appendix]{"version":"1.0"}
%---
