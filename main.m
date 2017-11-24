%%       Please Note: This is the raw unformatted copy. Thank you.       %%
%#########################################################################%
%Please include the reference below in your publication, if you find any  %
%part of this work useful                                                 %                                               
%                            Reference:                                   %
%O.G. Olaleye, M.A. Iqbal, A. Aly, D. Perkins, M. Bayoumi, "An Energy-    %
%Detection-based Cooperative Spectrum Sensing Scheme for Minimizing the   % 
%Effects of NPEE and RSPF," MSWiM ’16, November 13-17, 2016, Malta, Malta  %
%																		  %
%#########################################################################%
%#########################################################################%
% Author:  Oladiran G. Olaleye                                            %
% Project: Simulation of Energy Spectrum Sensing for Spectrum Awareness:  %
%          A Novel Scheme for Minimizing the Effects of Noise Estimation  %
%          Error and Malicious Attacks in Energy-Detection-based          %
%          Cooperative Spectrum Sensing for Spectrum Situational Awareness%
% School:  The Center for Advanced Computer Studies                       %
%          University of Louisiana at Lafayette                           %
% Email:   ogo8842@louisiana.edu                                          %
% Website: http://web.cacs.louisiana.edu/labs/wisper/index.html           %
%                                                                         %
%   						   02/15/2015                                 %
%						      Copyright(c)								  %
%#########################################################################%
%% This code plots:
% (a) Receiver Operating Characteristics (ROC) curves, 
% (b) Sensing Time versus  Number of Secondary Users (SUs), and
% (c) Throughput versus  Number of Secondary Users (SUs) for 
%     an IEEE 802.22 TV White Space (TVWS) Network based on
%     the FCC Longley-Rice Pathloss Model and 
%     the ITS Irregular Terrain model. 
%
%% List of Assumptions: 
% 1) Additive White Guassian Noise (AWGN);
% 2)
%
%%
%
%----------------------------- BEGIN CODE --------------------------------%
%% Start Simulation
clear all; close all; clc
set(0,'defaultAxesFontName', 'Times New Roman');

%% Simulation Parameters:
Signal_bandwidth = 6*10^6; % Hz (unit)
sensing_time = 0.2; % milliSeconds (unit) 
Pf_vector = 0.01:0.01:1; % Probability of false alarm
numSamples = 2 * (sensing_time/10^3) * (Signal_bandwidth); % Number of samples
num_SecondaryUsers = 60; % Number of secondary users
snr_vector = ones(num_SecondaryUsers,1); % Signal to Noise ratio, SNR
graph_ID = ('ox+dv^psh*ox+dv^psh*ox+dv^psh*'); % Plot identifiers
graph_ID2 = ('do^s+'); % Plot identifiers
graph_color = ('bbbkrrrb');
graph_color2 = ('ccckgggc');
graph_color3 = ('kbgcrmy');
graphMarker_size = [5 7 6 10 5];

% Initializing variables for case A
Qf_AND_caseA = ones(num_SecondaryUsers,1); % Initializing AND-fused false alarm probability
Qd_AND_caseA = ones(num_SecondaryUsers,1); % Initializing AND-fused detection probability
Qf_OR_caseA = ones(num_SecondaryUsers,1); % Initializing OR-fused false alarm probability
Qd_OR_caseA = ones(num_SecondaryUsers,1); % Initializing OR-fused detection probability
Qf_Majority_caseA = zeros(num_SecondaryUsers,1); % Initializing OR-fused false alarm probability
Qd_Majority_caseA = zeros(num_SecondaryUsers,1); % Initializing OR-fused detection probability
Qf_Voting_caseA = zeros(num_SecondaryUsers,1); % Initializing OR-fused false alarm probability
Qd_Voting_caseA = zeros(num_SecondaryUsers,1); % Initializing OR-fused detection probability
Qf_enhanced_DSrule_caseA = ones(num_SecondaryUsers,1); % Initializing Enhanced-DS-rule-fused false alarm probability
Qd_enhanced_DSrule_caseA = ones(num_SecondaryUsers,1); % Initializing Enhanced-DS-rule-fused detection probability
Qfd_enhanced_DSrule_caseA = ones(num_SecondaryUsers,1); % Probability of detection or false alarm

% Initializing variables for case B
Qf_AND_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Initializing AND-fused false alarm probability
Qd_AND_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Initializing AND-fused detection probability
Qf_OR_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_OR_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Majority_caseB = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Majority_caseB = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseB = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseB = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_enhanced_DSrule_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Initializing Enhanced-DS-rule-fused false alarm probability
Qd_enhanced_DSrule_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Initializing Enhanced-DS-rule-fused detection probability
Qfd_enhanced_DSrule_caseB = ones(num_SecondaryUsers,length(Pf_vector)); % Probability of detection or false alarm

% Initializing variables for case C
Qf_Voting_caseC = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseC = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseC_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseC_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseC_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseC_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseC_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseC_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseC_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseC_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseC_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseC_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case N
Qf_Voting_caseN = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseN = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseN_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseN_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseN_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseN_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseN_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseN_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseN_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseN_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseN_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseN_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case P
Qf_Voting_caseP = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseP = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseP_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseP_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseP_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseP_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseP_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseP_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseP_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseP_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseP_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseP_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case R
Qf_Voting_caseR = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseR = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseR_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseR_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseR_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseR_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseR_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseR_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseR_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseR_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseR_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseR_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case T
Qf_Voting_caseT = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseT = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseT_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseT_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseT_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseT_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseT_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseT_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseT_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseT_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseT_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseT_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case V
Qf_Voting_caseV = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseV = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseV_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseV_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseV_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseV_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseV_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseV_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseV_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseV_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseV_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseV_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case D
Qf_Voting_caseD = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseD = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseD_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseD_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseD_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseD_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseD_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseD_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseD_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseD_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseD_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseD_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

% Initializing variables for case E
Qf_Voting_caseE = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseE = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseE_withMalicious_lowSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseE_withMalicious_highSignal = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseE_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseE_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseE_withMalicious_lowSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseE_withMalicious_highSignal_SNRweighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qf_Voting_caseE_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
Qd_Voting_caseE_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseE_withMalicious_lowSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
Qd_Voting_caseE_withMalicious_highSignal_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability

%% Longley-Rice Pathloss
% Frequency = 600; % MHz (unit)
% Antenna Height (Primary User) = 305.0 m (effective height = 305.0 m)
% Antenna Height (secondary User) = 9.0 m (effective height = 17.2 m)
% Average Terrain (Hill) = 90.0 m
% Polarization = Horizontal
% Dielectric Constant of ground, esp = 15
% Conductivity of ground, sgm = 0.005 S/m
% Climate = Continental Temperate
% Surface Refractivity, Ns = 301 N-units
% Reliability = 50percent time, 50percent locations
% Mode of variability = Broadcast
% Confidence Level = 100%
[LongleyRice_dataset]=importdata('Longley-Rice_PathLoss.txt');
radialDistance_fromPU = ones(num_SecondaryUsers,1);
radialDistance_fromPU_raWdata = 1000.*LongleyRice_dataset.data(:,1); % m (unit)
pathLoss = LongleyRice_dataset.data(:,3); % In dimensionless unit

%% Reference Thermal Noise Density Level
% Noise Density Level = Boltzman Constant + 10*log(Reference Noise Temperature)
% Boltzman Constant = -138.6 dB(mW/(K × MHz))
% Reference Noise Temperature = 290 K (degrees Kelvin)
noise_avgPower_actual = -65.0; % dBm (unit)
noise_vector_actual = ones(1,num_SecondaryUsers).* noise_avgPower_actual;
PN = repmat(10.^(noise_vector_actual'./10),1,length(Pf_vector));

%% Primary User (TV) Signal
% Minimum requirements of -10 dBk (100 watts) horizontally polarized visual effective
% radiated power in any horizontal direction.
% https://transition.fcc.gov/mb/audio/bickel/amfmrule.html
%Pt_PU = 10*log10(1000); % dBm (unit)
Pt_PU = 50; % dBm EIRP (unit)
primarySignal_vector = ones(1,num_SecondaryUsers).* Pt_PU;
receivedSignalVector = primarySignal_vector' - pathLoss(1:500:num_SecondaryUsers*500);
radialDistance_fromPU = radialDistance_fromPU_raWdata(1:500:num_SecondaryUsers*500); % Changes due to pathloss offset
PS = repmat(10.^(receivedSignalVector./10),1,length(Pf_vector));

%% Signal to Noise Ratio, SNR @ Secondary Users (SU)
snr_vector = receivedSignalVector - noise_vector_actual';
snr_at_SU = repmat(snr_vector,1,length(Pf_vector)); % SNR matrix

%% Probability of False Alarm, Pf
Pf = repmat(Pf_vector,length(snr_vector),1);

%% Energy Threshold [ref: Y. C. Liang, "Sensing Throughput Tradeoff in Cognitive Radio"]
% threshold_Energy = 2.*gammaincinv(1-Pf,numSamples);
threshold_Energy = (qfuncinv(Pf)./sqrt(numSamples)) + 1;

%% Probability of Detection, Pd at SU's [ref: Y. C. Liang, "Sensing Throughput Tradeoff in Cognitive Radio"]
%Pd = marcumq(sqrt(2.*(10.^(snr_at_SU./10))), sqrt(threshold_Energy), numSamples);
Pd = qfunc(((threshold_Energy - (10.^(snr_at_SU./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU./10)) + 1)));

%% Plotting ROC Curve (Qf versus Qd)
figure(1)
for i=1:10:length(Pf_vector)
    if (i>1) i=i-1; end
    plot(snr_at_SU(:,i), Pd(:,i)), axis square
    hold on;
    title('SNR versus Probability of Detection ({\itP}_D) for an AWGN Channel with 0<={\itP}_{FA}<=1.0');
    grid on
    axis([-25,0.0,0.0,1.0]);
    text(snr_at_SU(ceil(0.35*length(snr_at_SU(:,i))),i),Pd(ceil(0.35*length(Pd(:,i))),i),['{\itP}_{FA} = ',num2str(Pf(1,i))], ...
        'Color', 'k', ...
        'EdgeColor','k', ...
        'BackgroundColor', 'w', ...
        'FontSize',10, ...        
        'Rotation',0, ...     
        'Margin',1.5, ...         
        'HorizontalAlignment', 'Center');    
    xlabel('Signal-to-Noise Ratio (dB)','FontSize',10);
    ylabel('Probability of Detection','FontSize',10);
end

%% CASE A: Comparing the Performance of Data Fusion Methods as the Number
%  of Secondary Users increase using SU's each with SNR=-11.6dB; Pf=0.1;
%  Pd=0.9183.
Pf_caseA = 0.1;
threshold_Energy_caseA = (qfuncinv(Pf_caseA)./sqrt(numSamples)) + 1;
SNR_caseA = -11.6; % dBm (unit)
Pd_caseA = qfunc(((threshold_Energy_caseA - (10.^(SNR_caseA./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(SNR_caseA./10)) + 1)));
Pfd_caseA = 1 - Pf_caseA - Pd_caseA; 

for k = 1:num_SecondaryUsers
        % Fusion by AND rule
        Qf_AND_caseA(k) = Pf_caseA ^ k;
        Qd_AND_caseA(k) = Pd_caseA ^ k;
        % Fusion by OR rule
        Qf_OR_caseA(k) = 1 - (1-Pf_caseA) ^ k;
        Qd_OR_caseA(k) = 1 - (1-Pd_caseA) ^ k;
        % Fusion by Majority rule with k=0.5
        for mm = ceil(k/2):k
            Qf_Majority_caseA(k) = (Pf_caseA)^mm * (1-Pf_caseA)^(k-mm) + Qf_Majority_caseA(k);
            Qd_Majority_caseA(k) = (Pd_caseA)^mm * (1-Pd_caseA)^(k-mm) + Qd_Majority_caseA(k);                         
        end
        % Fusion by Voting rule with T=0.5
        for nn = ceil(k/2):k
            Qf_Voting_caseA(k) = factorial(k)/(factorial(nn)*factorial(k-nn)) * (Pf_caseA)^nn * (1-Pf_caseA)^(k-nn) + Qf_Voting_caseA(k);
            Qd_Voting_caseA(k) = factorial(k)/(factorial(nn)*factorial(k-nn)) * (Pd_caseA)^nn * (1-Pd_caseA)^(k-nn) + Qd_Voting_caseA(k);
        end         
        % Fusion by Enhanced Dempster-Shafer Theory [ref]       
        if (k < 2)
            Qf_enhanced_DSrule_caseA(1) = Pf_caseA;
            Qd_enhanced_DSrule_caseA(1) = Pd_caseA;
            Qfd_enhanced_DSrule_caseA(1) = Pfd_caseA; 
        else
            k_DS = Qd_enhanced_DSrule_caseA(k-1)*Pf_caseA + Pd_caseA*Qf_enhanced_DSrule_caseA(k-1);
            Qf_enhanced_DSrule_caseA(k) = (Qf_enhanced_DSrule_caseA(k-1)*Pf_caseA + Qf_enhanced_DSrule_caseA(k-1)*Pfd_caseA + Pf_caseA*Qfd_enhanced_DSrule_caseA(k-1))/(1-k_DS);
            Qd_enhanced_DSrule_caseA(k) = (Qd_enhanced_DSrule_caseA(k-1)*Pd_caseA + Qd_enhanced_DSrule_caseA(k-1)*Pfd_caseA + Pd_caseA*Qfd_enhanced_DSrule_caseA(k-1))/(1-k_DS);
            Qfd_enhanced_DSrule_caseA(k) = 1 - Qf_enhanced_DSrule_caseA(k) - Qd_enhanced_DSrule_caseA(k);
        end
end

%% Plotting Number of SU's versus Pd for the SU's
figure(2)
plot(1:1:num_SecondaryUsers,Qf_AND_caseA,'k-*',1:1:num_SecondaryUsers,Qd_AND_caseA,'k-p',...
     1:1:num_SecondaryUsers,Qf_OR_caseA,'b-^',1:1:num_SecondaryUsers,Qd_OR_caseA,'b-d',...
     1:1:num_SecondaryUsers,Qf_Majority_caseA,'r-s',1:1:num_SecondaryUsers,Qd_Majority_caseA,'r-+',...
     1:1:num_SecondaryUsers,Qf_Voting_caseA,'c-<',1:1:num_SecondaryUsers,Qd_Voting_caseA,'c->',...
     1:1:num_SecondaryUsers,Qf_enhanced_DSrule_caseA,'g-o',1:1:num_SecondaryUsers,Qd_enhanced_DSrule_caseA,'g-v')
title('Number of SUs versus Probability of Detection ({\itP}_D) for comparing Data Fusion Methods using SUs each with SNR=-11.6dB, {\itP}_{FA}=0.1 and {\itP}_D=0.9183');
grid on
axis([1,num_SecondaryUsers/3,0.0,1]);
xlabel('Number of Secondary Users ({\itN}_{SU})');
ylabel('Fused Probability of False Alarm ({\itQ}_F) and Probability of Detection ({\itQ}_D)');
legend('{\itQ}_F, AND rule','{\itQ}_D, AND rule','{\itQ}_F, OR rule','{\itQ}_D, OR rule',...
       '{\itQ}_F, Majority rule with {\itk}=0.5','{\itQ}_D, Majority rule with {\itk}=0.5',...
       '{\itQ}_F, Voting rule with {\itT}=0.5','{\itQ}_D, Voting rule with {\itT}=0.5',...       
       '{\itQ}_F, Dempster-Shafer rule','{\itQ}_D, Dempster-Shafer rule');

%% CASE B: Performance Comparison of Data Fusion Methods based on ROC using
%  SU's with SNR=-20.0dB; 0.0<=Pf<=1.0.
Pf_caseB = repmat(Pf(20,1:1:length(Pf_vector)),num_SecondaryUsers,1);
Pd_caseB = repmat(Pd(20,1:1:length(Pf_vector)),num_SecondaryUsers,1);
Pfd_caseB = 1 - Pf_caseB - Pd_caseB;
SNR_caseB = repmat(10.^(snr_at_SU(17,1:1:length(Pf_vector))./10),num_SecondaryUsers,1);

for k = 1:num_SecondaryUsers
        % Fusion by AND rule
        Qf_AND_caseB(k,:) = Pf_caseB(k,:) .^ k;
        Qd_AND_caseB(k,:) = Pd_caseB(k,:) .^ k;
        % Fusion by OR rule
        Qf_OR_caseB(k,:) = 1 - (1-Pf_caseB(k,:)) .^ k;
        Qd_OR_caseB(k,:) = 1 - (1-Pd_caseB(k,:)) .^ k;
        % Fusion by Majority rule with k=0.5
        for mm = ceil(k/2):k
            Qf_Majority_caseB(k,:) = (Pf_caseB(k,:)).^mm .* (1-Pf_caseB(k,:)).^(k-mm) + Qf_Majority_caseB(k);
            Qd_Majority_caseB(k,:) = (Pd_caseB(k,:)).^mm .* (1-Pd_caseB(k,:)).^(k-mm) + Qd_Majority_caseB(k);                         
        end           
        % Fusion by Voting rule with T=0.5
        for nn = ceil(k/2):k
            Qf_Voting_caseB(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseB(k,:)).^nn .* (1-Pf_caseB(k,:)).^(k-nn) + Qf_Voting_caseB(k,:);
            Qd_Voting_caseB(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseB(k,:)).^nn .* (1-Pd_caseB(k,:)).^(k-nn) + Qd_Voting_caseB(k,:);            
        end                   
        % Fusion by Enhanced Dempster-Shafer Theory [ref]       
        if (k < 2)
            Qf_enhanced_DSrule_caseB(1,:) = Pf_caseB(1,:);
            Qd_enhanced_DSrule_caseB(1,:) = Pd_caseB(1,:);
            Qfd_enhanced_DSrule_caseB(1,:) = Pfd_caseB(1,:); 
        else
            k_DS = Qd_enhanced_DSrule_caseB(k-1,:).*Pf_caseB(k,:) + Pd_caseB(k,:).*Qf_enhanced_DSrule_caseB(k-1,:);
            Qf_enhanced_DSrule_caseB(k,:) = (Qfd_enhanced_DSrule_caseB(k-1,:).*Pfd_caseB(k,:) + Qf_enhanced_DSrule_caseB(k-1,:).*Pfd_caseB(k,:) + Pf_caseB(k,:).*Qfd_enhanced_DSrule_caseB(k-1,:))./(1-k_DS);
            Qd_enhanced_DSrule_caseB(k,:) = (Qfd_enhanced_DSrule_caseB(k-1,:).*Pfd_caseB(k,:) + Qd_enhanced_DSrule_caseB(k-1,:).*Pfd_caseB(k,:) + Pd_caseB(k,:).*Qfd_enhanced_DSrule_caseB(k-1,:))./(1-k_DS);
            Qfd_enhanced_DSrule_caseB(k,:) = 1 - Qf_enhanced_DSrule_caseB(k,:) - Qd_enhanced_DSrule_caseB(k,:);
        end
end

%% Plotting ROC Curve for SU's with similar channel
figure(3)
plot(Qf_AND_caseB(10,:)',Qd_AND_caseB(10,:)','k-*',...
    Qf_OR_caseB(10,:)',Qd_OR_caseB(10,:)','b-^',...
    Qf_Majority_caseB(10,:)',Qd_Majority_caseB(10,:)','r-s',...
    Qf_Voting_caseB(10,:)',Qd_Voting_caseB(10,:)','c-<',...
Qf_enhanced_DSrule_caseB(10,1:1:39)',Qd_enhanced_DSrule_caseB(10,1:1:39)','g-o')
title('ROC Curve for 10 Secondary Users (SUs) each with SNR=-20.0dB and 0.0<={\itP}_{FA}<=1.0');
grid on
axis([0.25,0.75,0.0,1.0]);
xlabel('Fused Probability of False Alarm');
ylabel('Fused Probability of Detection');
legend('AND rule','OR rule','Majority rule','Voting rule with {\itT}=0.5','Dempster-Shafer rule');

%% Simulation of a 10-SU Cognitive Radio Network for comparing the
%  Proposed Scheme to the Conventional Cooperative Specrtrum Sensing Scheme
SNR_range = 12:1:21; % SNR Vector

%% CASE C: Conventional Method with Uniform Noise Power Estimation Error
%  (NPEE)
curvesX_caseC = ones(length(SNR_range),length(Pf));
curvesY_caseC = ones(length(SNR_range),length(Pf));
for num_model = 1:7
    noise_avgPower_caseC = -69.0+num_model; % dBm (un-it)
    noise_vector_caseC = ones(1,num_SecondaryUsers).* noise_avgPower_caseC;
    snr_vector_caseC = receivedSignalVector - noise_vector_caseC';
    snr_at_SU_caseC = repmat(snr_vector_caseC,1,length(Pf_vector)); % SNR matrix
    Pd_caseC_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseC./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseC./10)) + 1)));
    
    Pf_caseC = Pf(SNR_range,:);
    Pd_caseC = Pd_caseC_dataset(SNR_range,:);
    SNR_caseC = repmat(10.^(snr_at_SU_caseC(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseC = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseC(SNR_range,1) .* (radialDistance_fromPU_caseC).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseC,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseC_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseC;
    SNR_caseC_radiallyWeighted = repmat(SNR_caseC_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseC_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseC_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseC_radiallyWeighted + 1)));
    Qf_Voting_caseC = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseC = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseC_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseC_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseC(1,:) = Pf_caseC(1,:);
    Qd_Voting_caseC(1,:) = Pd_caseC(1,:);
    Qd_Voting_caseC_radiallyWeighted(1,:) = Pd_caseC_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5      
            for nn = ceil(k/2):k
                Qf_Voting_caseC(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseC(k,:)).^nn .* (1-Pf_caseC(k,:)).^(k-nn) + Qf_Voting_caseC(k,:);
                Qd_Voting_caseC(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseC(k,:)).^nn .* (1-Pd_caseC(k,:)).^(k-nn) + Qd_Voting_caseC(k,:);                        
            end
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseC_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseC_radiallyWeighted(k,:)).^nn .* (1-Pd_caseC_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseC_radiallyWeighted(k,:);
            end
    end
    curvesX_caseC(num_model,:) = Qf_Voting_caseC(length(SNR_range),:);
    curvesY_caseC(num_model,:) = Qd_Voting_caseC(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig4 = figure(4);

%% CASE N: Proposed Scheme with Uniform Noise Power Estimation Error (NPEE)
curvesX_caseN = ones(length(SNR_range),length(Pf));
curvesY_caseN = ones(length(SNR_range),length(Pf));
for num_model = 1:7
    noise_avgPower_caseN = -69.0+num_model; % dBm (unit)
    noise_vector_caseN = ones(1,num_SecondaryUsers).* noise_avgPower_caseN;
    
    noise_est_caseN = 10.^(noise_vector_caseN./10);
    noise_meas_caseN = 10.^(-65.0./10);
    reliability_est_caseN = 0.5 - 0.5.*abs(noise_est_caseN-noise_meas_caseN)./noise_meas_caseN;
    if (reliability_est_caseN(1,1) < 0.0), reliability_est_caseN(1,:) = 0.0; end
    reliability_meas_caseN = 1 - reliability_est_caseN;
    noise_vector_corr_caseN = reliability_est_caseN.*noise_est_caseN + reliability_meas_caseN.*noise_meas_caseN;
    noise_vector_corr_caseN = 10.*log10(noise_vector_corr_caseN);
    snr_vector_caseN = receivedSignalVector - noise_vector_corr_caseN';
    
    snr_at_SU_caseN = repmat(snr_vector_caseN,1,length(Pf_vector)); % SNR matrix
    Pd_caseN_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseN./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseN./10)) + 1)));
    Pf_caseN = Pf(SNR_range,:);
    Pd_caseN = Pd_caseN_dataset(SNR_range,:);
    
    SNR_caseN = repmat(10.^(snr_at_SU_caseN(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseN = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseN(SNR_range,1) .* (radialDistance_fromPU_caseN).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseN,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseN_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseN;
    SNR_caseN_radiallyWeighted = repmat(SNR_caseN_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseN_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseN_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseN_radiallyWeighted + 1)));
    Qf_Voting_caseN = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseN = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseN_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseN_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseN(1,:) = Pf_caseN(1,:);
    Qd_Voting_caseN(1,:) = Pd_caseN(1,:);
    Qd_Voting_caseN_radiallyWeighted(1,:) = Pd_caseN_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5      
            for nn = ceil(k/2):k
                Qf_Voting_caseN(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseN(k,:)).^nn .* (1-Pf_caseN(k,:)).^(k-nn) + Qf_Voting_caseN(k,:);
                Qd_Voting_caseN(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseN(k,:)).^nn .* (1-Pd_caseN(k,:)).^(k-nn) + Qd_Voting_caseN(k,:);                        
            end         
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseN_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseN_radiallyWeighted(k,:)).^nn .* (1-Pd_caseN_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseN_radiallyWeighted(k,:);
            end
    end
    curvesX_caseN(num_model,:) = Qf_Voting_caseN(length(SNR_range),:);
    curvesY_caseN(num_model,:) = Qd_Voting_caseN(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig5 = figure(5);

%% CASE T: Proposed Scheme versus Conventional Method based on Random Noise
%  Power Estimation Error (NPEE)
curvesX_caseT = ones(length(SNR_range),length(Pf));
curvesY_caseT = ones(length(SNR_range),length(Pf));
noise_vector_distr_caseT = (-70.0--60.0).*rand(1,num_SecondaryUsers) + -60.0;
for num_model = [4 1 7]
    if (num_model == 4)
        noise_vector_caseT = ones(1,num_SecondaryUsers).* -65; % dBm (unit)
    else
        noise_vector_caseT = noise_vector_distr_caseT; % dBm (unit)
    end
    
    if (num_model == 7)    
        noise_est_caseT = 10.^(noise_vector_caseT./10);
        noise_meas_caseT = 10.^(-65.0./10);
        reliability_est_caseT = 0.5 - 0.5.*abs(noise_est_caseT-noise_meas_caseT)./noise_meas_caseT;
        for ii = 1:num_SecondaryUsers
            if (reliability_est_caseT(1,ii) < 0.0), reliability_est_caseT(1,ii) = 0.0; end
        end
        reliability_meas_caseT = 1 - reliability_est_caseT;
        noise_vector_corr_caseT = reliability_est_caseT.*noise_est_caseT + reliability_meas_caseT.*noise_meas_caseT;
        noise_vector_caseT = 10.*log10(noise_vector_corr_caseT);
    end

    snr_vector_caseT = receivedSignalVector - noise_vector_caseT';
    snr_at_SU_caseT = repmat(snr_vector_caseT,1,length(Pf_vector)); % SNR matrix
    Pd_caseT_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseT./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseT./10)) + 1))); 
    Pf_caseT = Pf(SNR_range,:);
    Pd_caseT = Pd_caseT_dataset(SNR_range,:);
    SNR_caseT = repmat(10.^(snr_at_SU_caseT(SNR_range,1:1:length(Pf_vector))./10),1,1);
    
    SNR_radiallyWeighted_caseT = repmat(10.^(snr_at_SU_caseT(SNR_range,1:1:length(Pf_vector))./10),10,1);    
    radialDistance_fromPU_caseT = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_radiallyWeighted_caseT(SNR_range,1) .* (radialDistance_fromPU_caseT).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseT,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseT_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseT;
    SNR_caseT_radiallyWeighted = repmat(SNR_caseT_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseT_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseT_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseT_radiallyWeighted + 1)));
    Qf_Voting_caseT = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseT = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseT_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseT_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    
    Qf_Voting_caseT(1,:) = Pf_caseT(1,:);
    Qd_Voting_caseT(1,:) = Pd_caseT(1,:);
    Qd_Voting_caseT_radiallyWeighted(1,:) = Pd_caseT_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5  
            for nn = ceil(k/2):k
                Qf_Voting_caseT(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseT(k,:)).^nn .* (1-Pf_caseT(k,:)).^(k-nn) + Qf_Voting_caseT(k,:);
                Qd_Voting_caseT(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseT(k,:)).^nn .* (1-Pd_caseT(k,:)).^(k-nn) + Qd_Voting_caseT(k,:);                        
            end
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseT_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseT_radiallyWeighted(k,:)).^nn .* (1-Pd_caseT_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseT_radiallyWeighted(k,:);
            end
    end
    curvesX_caseT(num_model,:) = Qf_Voting_caseT(length(SNR_range),:);
    curvesY_caseT(num_model,:) = Qd_Voting_caseT(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig6 = figure(6);

%% CASE P: Conventional Method with Uniform Received Signal Power
%  Falsification (RSPF)
curvesX_caseP = ones(10,length(Pf));
curvesY_caseP = ones(10,length(Pf));
for num_model = 1:8
    noise_avgPower_caseP = -65.0; % dBm (unit)
    noise_vector_caseP = ones(1,num_SecondaryUsers).* noise_avgPower_caseP;
    if (num_model < 8)    
        snr_vector_caseP  = (num_model-4) + receivedSignalVector' - noise_vector_caseP;
    else
        snr_vector_caseP  = 2.*receivedSignalVector' - noise_vector_caseP;
    end
    snr_at_SU_caseP = repmat(snr_vector_caseP',1,length(Pf_vector)); % SNR matrix
    Pd_caseP_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseP./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseP./10)) + 1)));

    Pf_caseP = Pf(SNR_range,:);
    Pd_caseP = Pd_caseP_dataset(SNR_range,:);
    SNR_caseP = repmat(10.^(snr_at_SU_caseP(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseP = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseP(SNR_range,1) .* (radialDistance_fromPU_caseP).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseP,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseP_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseP;
    SNR_caseP_radiallyWeighted = repmat(SNR_caseP_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseP_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseP_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseP_radiallyWeighted + 1)));
    Qf_Voting_caseP = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseP = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseP_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseP_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseP(1,:) = Pf_caseP(1,:);
    Qd_Voting_caseP(1,:) = Pd_caseP(1,:);
    Qd_Voting_caseP_radiallyWeighted(1,:) = Pd_caseP_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5      
            for nn = ceil(k/2):k
                Qf_Voting_caseP(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseP(k,:)).^nn .* (1-Pf_caseP(k,:)).^(k-nn) + Qf_Voting_caseP(k,:);
                Qd_Voting_caseP(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseP(k,:)).^nn .* (1-Pd_caseP(k,:)).^(k-nn) + Qd_Voting_caseP(k,:);                        
            end         
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseP_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseP_radiallyWeighted(k,:)).^nn .* (1-Pd_caseP_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseP_radiallyWeighted(k,:);
            end
    end
    curvesX_caseP(num_model,:) = Qf_Voting_caseP(length(SNR_range),:);
    curvesY_caseP(num_model,:) = Qd_Voting_caseP(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig7 = figure(7);

%% CASE R: Proposed Scheme with Uniform Received Signal Power Falsification
%  (RSPF)
curvesX_caseR = ones(length(SNR_range),length(Pf));
curvesY_caseR = ones(length(SNR_range),length(Pf));
for num_model = 1:8
    noise_avgPower_caseR = -65.0; % dBm (unit)
    noise_vector_caseR = ones(1,num_SecondaryUsers).* noise_avgPower_caseR;

    signal_pred_caseR = 10.^(receivedSignalVector./10);
    if (num_model < 8) 
        signal_meas_caseR = 10.^(((num_model-4) + receivedSignalVector)./10);
    else
        signal_meas_caseR = 10.^((2.*receivedSignalVector)./10);
    end
    reliability_meas_caseR = 0.5 - 0.5.*abs(signal_meas_caseR-signal_pred_caseR)./signal_pred_caseR;
    if (reliability_meas_caseR(1,1) < 0.0), reliability_meas_caseR(1,:) = 0.0; end
    reliability_pred_caseR = 1 - reliability_meas_caseR;
    signal_vector_corr_caseR = reliability_meas_caseR.*signal_meas_caseR + reliability_pred_caseR.*signal_pred_caseR;
    signal_vector_corr_caseR = 10.*log10(signal_vector_corr_caseR);
    snr_vector_caseR = signal_vector_corr_caseR - noise_vector_caseR';
    
    snr_at_SU_caseR = repmat(snr_vector_caseR,1,length(Pf_vector)); % SNR matrix
    Pd_caseR_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseR./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseR./10)) + 1)));
    Pf_caseR = Pf(SNR_range,:);
    Pd_caseR = Pd_caseR_dataset(SNR_range,:);

    SNR_caseR = repmat(10.^(snr_at_SU_caseR(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseR = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseR(SNR_range,1) .* (radialDistance_fromPU_caseR).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseR,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseR_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseR;
    SNR_caseR_radiallyWeighted = repmat(SNR_caseR_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseR_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseR_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseR_radiallyWeighted + 1)));
    Qf_Voting_caseR = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseR = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseR_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseR_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseR(1,:) = Pf_caseR(1,:);
    Qd_Voting_caseR(1,:) = Pd_caseR(1,:);
    Qd_Voting_caseR_radiallyWeighted(1,:) = Pd_caseR_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5      
            for nn = ceil(k/2):k
                Qf_Voting_caseR(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseR(k,:)).^nn .* (1-Pf_caseR(k,:)).^(k-nn) + Qf_Voting_caseR(k,:);
                Qd_Voting_caseR(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseR(k,:)).^nn .* (1-Pd_caseR(k,:)).^(k-nn) + Qd_Voting_caseR(k,:);                        
            end 
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseR_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseR_radiallyWeighted(k,:)).^nn .* (1-Pd_caseR_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseR_radiallyWeighted(k,:);
            end
    end 
    curvesX_caseR(num_model,:) = Qf_Voting_caseR(length(SNR_range),:);
    curvesY_caseR(num_model,:) = Qd_Voting_caseR(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig8 = figure(8);

%% CASE D: Conventional Method with Slight and Total Uniform RSPF and
%  Number of Malicious Users.
curvesX_caseD = ones(10,length(Pf));
curvesY_caseD = ones(10,length(Pf));
for num_model = 1:5
    noise_avgPower_caseD = -65.0; % dBm (unit)
    noise_vector_caseD = ones(1,num_SecondaryUsers).* noise_avgPower_caseD;
    receivedSignalVector_caseD = receivedSignalVector;
    if (num_model==2)      
        receivedSignalVector_caseD(12:16,1) = -2 + receivedSignalVector_caseD(12:16,1);
    elseif (num_model==3)
        receivedSignalVector_caseD(12:21,1) = -2 + receivedSignalVector_caseD(12:21,1);
    elseif (num_model==4)
        receivedSignalVector_caseD(12:16,1) = 2.*receivedSignalVector_caseD(12:16,1);
    elseif (num_model==5)
        receivedSignalVector_caseD(12:21,1) = 2.*receivedSignalVector_caseD(12:21,1);      
    else
    end
    snr_vector_caseD  = receivedSignalVector_caseD' - noise_vector_caseD;
    snr_at_SU_caseD = repmat(snr_vector_caseD',1,length(Pf_vector)); % SNR matrix
    Pd_caseD_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseD./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseD./10)) + 1)));

    Pf_caseD = Pf(SNR_range,:);
    Pd_caseD = Pd_caseD_dataset(SNR_range,:);
    SNR_caseD = repmat(10.^(snr_at_SU_caseD(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseD = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseD(SNR_range,1) .* (radialDistance_fromPU_caseD).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseD,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseD_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseD;
    SNR_caseD_radiallyWeighted = repmat(SNR_caseD_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseD_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseD_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseD_radiallyWeighted + 1)));
    Qf_Voting_caseD = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseD = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseD_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseD_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseD(1,:) = Pf_caseD(1,:);
    Qd_Voting_caseD(1,:) = Pd_caseD(1,:);
    Qd_Voting_caseD_radiallyWeighted(1,:) = Pd_caseD_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5     
            for nn = ceil(k/2):k
                Qf_Voting_caseD(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseD(k,:)).^nn .* (1-Pf_caseD(k,:)).^(k-nn) + Qf_Voting_caseD(k,:);
                Qd_Voting_caseD(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseD(k,:)).^nn .* (1-Pd_caseD(k,:)).^(k-nn) + Qd_Voting_caseD(k,:);                        
            end
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseD_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseD_radiallyWeighted(k,:)).^nn .* (1-Pd_caseD_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseD_radiallyWeighted(k,:);
            end
    end
    curvesX_caseD(num_model,:) = Qf_Voting_caseD(length(SNR_range),:);
    curvesY_caseD(num_model,:) = Qd_Voting_caseD(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig9 = figure(9);

%% CASE E: Proposed Scheme with Slight and Total Uniform RSPF and Number of
%  Malicious Users.
curvesX_caseE = ones(10,length(Pf));
curvesY_caseE = ones(10,length(Pf));
for num_model = 1:5
    noise_avgPower_caseE = -65.0; % dBm (unit)
    noise_vector_caseE = ones(1,num_SecondaryUsers).* noise_avgPower_caseE;
    receivedSignalVector_caseE = receivedSignalVector;
    if (num_model==2)
        receivedSignalVector_caseE(12:16,1) = -2 + receivedSignalVector_caseE(12:16,1);
    elseif (num_model==3)
        receivedSignalVector_caseE(12:21,1) = -2 + receivedSignalVector_caseE(12:21,1);
    elseif (num_model==4)
        receivedSignalVector_caseE(12:16,1) = 2.*receivedSignalVector_caseE(12:16,1);
    elseif (num_model==5)
        receivedSignalVector_caseE(12:21,1) = 2.*receivedSignalVector_caseE(12:21,1);      
    else
    end
    
    signal_pred_caseE = 10.^(receivedSignalVector./10);
    signal_meas_caseE = 10.^((receivedSignalVector_caseE)./10);
    reliability_meas_caseE = 0.5 - 0.5.*abs(signal_meas_caseE-signal_pred_caseE)./signal_pred_caseE;
    if (reliability_meas_caseE(1,1) < 0.0), reliability_meas_caseE(1,:) = 0.0; end
    reliability_pred_caseE = 1 - reliability_meas_caseE;
    signal_vector_corr_caseE = reliability_meas_caseE.*signal_meas_caseE + reliability_pred_caseE.*signal_pred_caseE;
    signal_vector_corr_caseE = 10.*log10(signal_vector_corr_caseE);
    snr_vector_caseE = signal_vector_corr_caseE - noise_vector_caseE';
    snr_at_SU_caseE = repmat(snr_vector_caseE,1,length(Pf_vector)); % SNR matrix
    Pd_caseE_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseE./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseE./10)) + 1)));

    Pf_caseE = Pf(SNR_range,:);
    Pd_caseE = Pd_caseE_dataset(SNR_range,:);
    SNR_caseE = repmat(10.^(snr_at_SU_caseE(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseE = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseE(SNR_range,1) .* (radialDistance_fromPU_caseE).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseE,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseE_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseE;
    SNR_caseE_radiallyWeighted = repmat(SNR_caseE_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseE_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseE_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseE_radiallyWeighted + 1)));
    Qf_Voting_caseE = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseE = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseE_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseE_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseE(1,:) = Pf_caseE(1,:);
    Qd_Voting_caseE(1,:) = Pd_caseE(1,:);
    Qd_Voting_caseE_radiallyWeighted(1,:) = Pd_caseE_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5     
            for nn = ceil(k/2):k
                Qf_Voting_caseE(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseE(k,:)).^nn .* (1-Pf_caseE(k,:)).^(k-nn) + Qf_Voting_caseE(k,:);
                Qd_Voting_caseE(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseE(k,:)).^nn .* (1-Pd_caseE(k,:)).^(k-nn) + Qd_Voting_caseE(k,:);                        
            end
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseE_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseE_radiallyWeighted(k,:)).^nn .* (1-Pd_caseE_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseE_radiallyWeighted(k,:);
            end
    end
    curvesX_caseE(num_model,:) = Qf_Voting_caseE(length(SNR_range),:);
    curvesY_caseE(num_model,:) = Qd_Voting_caseE(length(SNR_range),:);
end
%% Plotting the ROC Curve
Fig10 = figure(10);

%% CASE V:  Proposed Scheme versus Conventional Method based on Random
%  Received Signal Power Falsification (RSPF)
    curvesX_caseV = ones(length(SNR_range),length(Pf));
    curvesY_caseV = ones(length(SNR_range),length(Pf));
    noise_avgPower_caseV = -65.0; % dBm (unit)
    noise_vector_caseV = ones(1,num_SecondaryUsers).* noise_avgPower_caseV;
    ReceivedprimarySignal_vector_falsified_caseV = ((5--5).*rand(1,num_SecondaryUsers) + -5) + receivedSignalVector';
for num_model = [4 1 7]
    
    if (num_model == 7)
        signal_meas_caseV = 10.^(ReceivedprimarySignal_vector_falsified_caseV./10);
        signal_pred_caseV = 10.^(receivedSignalVector'./10);
        reliability_meas_caseV = 0.5 - 0.5.*abs(signal_meas_caseV-signal_pred_caseV)./signal_pred_caseV;
        for ii = 1:num_SecondaryUsers
            if (reliability_meas_caseV(1,ii) < 0.0), reliability_meas_caseV(1,ii) = 0.0; end
        end
        reliability_pred_caseV = 1 - reliability_meas_caseV;
        signal_vector_corr_caseV = reliability_meas_caseV.*signal_meas_caseV + reliability_pred_caseV.*signal_pred_caseV;
        ReceivedprimarySignal_vector_falsified_caseV = 10.*log10(signal_vector_corr_caseV);
    end    
 
    if (num_model == 4)
        snr_vector_caseV = receivedSignalVector' - noise_vector_caseV;
    else
        snr_vector_caseV = ReceivedprimarySignal_vector_falsified_caseV - noise_vector_caseV;        
    end
    snr_at_SU_caseV = repmat(snr_vector_caseV',1,length(Pf_vector)); % SNR matrix
    Pd_caseV_dataset = qfunc(((threshold_Energy - (10.^(snr_at_SU_caseV./10) + 1)).*sqrt(numSamples)) ./ (sqrt(2).*((10.^(snr_at_SU_caseV./10)) + 1))); 
    Pf_caseV = Pf(SNR_range,:);
    Pd_caseV = Pd_caseV_dataset(SNR_range,:);

    SNR_caseV = repmat(10.^(snr_at_SU_caseV(SNR_range,1:1:length(Pf_vector))./10),10,1);
    radialDistance_fromPU_caseV = radialDistance_fromPU(SNR_range);
    snrDistanceProduct = SNR_caseV(SNR_range,1) .* (radialDistance_fromPU_caseV).^1.22975;
    average_snrDistanceProduct = mean(snrDistanceProduct);
    absoluteDeviation_snrDistanceProduct = abs(snrDistanceProduct - average_snrDistanceProduct);
    [minimumDeviation_snrDistanceProduct_caseV,index_minDeviation_snrDistanceProduct] = min(absoluteDeviation_snrDistanceProduct);
    SNR_caseV_radiallyWeighted_vector = snrDistanceProduct(index_minDeviation_snrDistanceProduct) ./ radialDistance_fromPU_caseV;
    SNR_caseV_radiallyWeighted = repmat(SNR_caseV_radiallyWeighted_vector,1,length(Pf_vector));
    Pd_caseV_radiallyWeighted = qfunc(((threshold_Energy(SNR_range,1:1:length(Pf_vector)) - (SNR_caseV_radiallyWeighted + 1)).*sqrt(numSamples)) ./ (sqrt(2).*(SNR_caseV_radiallyWeighted + 1)));
    Qf_Voting_caseV = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseV = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseV_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused false alarm probability
    Qd_Voting_caseV_radiallyWeighted = zeros(num_SecondaryUsers,length(Pf_vector)); % Initializing OR-fused detection probability
    Qf_Voting_caseV(1,:) = Pf_caseV(1,:);
    Qd_Voting_caseV(1,:) = Pd_caseV(1,:);
    Qd_Voting_caseV_radiallyWeighted(1,:) = Pd_caseV_radiallyWeighted(1,:);
    for k = 2:length(SNR_range) % num_SecondaryUsers
            % Fusion by Voting rule with T=0.5      
            for nn = ceil(k/2):k
                Qf_Voting_caseV(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pf_caseV(k,:)).^nn .* (1-Pf_caseV(k,:)).^(k-nn) + Qf_Voting_caseV(k,:);
                Qd_Voting_caseV(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseV(k,:)).^nn .* (1-Pd_caseV(k,:)).^(k-nn) + Qd_Voting_caseV(k,:);                        
            end
            % Fusion by Voting rule with T=0.5 with radially weighted SNR
            for nn = ceil(k/2):k
                Qd_Voting_caseV_radiallyWeighted(k,:) = factorial(k)/(factorial(nn)*factorial(k-nn)) .* (Pd_caseV_radiallyWeighted(k,:)).^nn .* (1-Pd_caseV_radiallyWeighted(k,:)).^(k-nn) + Qd_Voting_caseV_radiallyWeighted(k,:);
            end
    end
    curvesX_caseV(num_model,:) = Qf_Voting_caseV(length(SNR_range),:);
    curvesY_caseV(num_model,:) = Qd_Voting_caseV(length(SNR_range),:);
end
%% Plotting ROC Curve for 
Fig11 = figure(11);

%%

%---------------------------- END OF CODE --------------------------------%
