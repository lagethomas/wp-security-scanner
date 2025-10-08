jQuery(document).ready(function($) {
    
    // Prefixos para evitar colisões
    var WPSS_PREFIX = 'wpss_';
    
    // Handler para o botão de iniciar o scan
    $('#run-scan').on('click', runScan);

    // Handler para a funcionalidade do acordeão (EXPANDIR/REDUZIR)
    $('#results-accordion-wrapper').on('click', '.accordion-header', function() {
        var $header = $(this);
        var $content = $header.next('.accordion-content');
        
        // Fechar todos os outros
        $('.accordion-content').not($content).slideUp(200);
        $('.accordion-header').not($header).removeClass('active');
        
        // Abrir/fechar o clicado
        $content.slideToggle(300);
        $header.toggleClass('active');
    });

    // Função principal para iniciar o scan
    function runScan() {
        var $button = $('#run-scan');
        var $resultsMessage = $('#scan-results');
        var $progressContainer = $('#scan-progress-bar');
        
        // Inicialização do UI
        $button.prop('disabled', true).text('Escaneando...');
        $progressContainer.show();
        $resultsMessage.html('<div class="notice notice-info"><p>🔄 Iniciando verificação completa do sistema...</p></div>');
        $('#results-accordion-wrapper').hide().empty();
        
        var sectionsMap = healthCheckAjax.scan_steps; // Mapa de slugs e data (title) do PHP
        var sectionsSlugs = Object.keys(sectionsMap); // Array de slugs (keys)
        var totalSteps = sectionsSlugs.length;
        var currentStep = 0;
        
        // Função para atualizar a barra de progresso
        function updateProgress() {
            if (currentStep < totalSteps) {
                 // Pega o título da seção atual para exibir
                var stepTitle = sectionsMap[sectionsSlugs[currentStep]].title;
                
                var percentage = Math.min(100, Math.round((currentStep / totalSteps) * 100));
                
                $('#progress-text').text('Verificando: ' + stepTitle + '...');
                $('#progress-percentage').text(percentage + '%');
                $('#progress-bar-fill').css('width', percentage + '%');
            }
            currentStep++;
        }
        
        // Inicia o processo de atualização de progresso
        var progressInterval = setInterval(function() {
            if (currentStep <= totalSteps) {
                updateProgress();
            } else {
                clearInterval(progressInterval);
            }
        }, 600); // Atualiza a barra a cada 600ms

        $.ajax({
            url: healthCheckAjax.ajax_url,
            type: 'POST',
            data: {
                action: healthCheckAjax.ajax_action, // Usando a action do PHP
                nonce: healthCheckAjax.nonce
            },
            success: function(response) {
                if (response.success) {
                    // Garante que o progresso chegue a 100% no sucesso
                    clearInterval(progressInterval);
                    $('#progress-text').text('Verificação concluída!');
                    $('#progress-percentage').text('100%');
                    $('#progress-bar-fill').css('width', '100%').css('background', 'var(--wpss-success)');
                    
                    displayResults(response.data, sectionsMap);
                } else {
                    var errorMessage = response.data && response.data.message ? response.data.message : 'Erro desconhecido ao executar scan.';
                    $resultsMessage.html('<div class="notice notice-error"><p>❌ Erro ao executar scan: ' + errorMessage + '</p></div>');
                }
            },
            error: function() {
                $resultsMessage.html('<div class="notice notice-error"><p>❌ Erro de conexão com o servidor.</p></div>');
            },
            complete: function() {
                $button.prop('disabled', false).text('🔍 Executar Verificação Completa');
                
                // Reset após um breve atraso
                setTimeout(function() {
                    $progressContainer.hide();
                    $('#progress-bar-fill').css('width', '0%').css('background', 'var(--wpss-primary)');
                }, 2000);
            }
        });
    }
    
    // Função para exibir os resultados no Acordeão
    function displayResults(results, sectionsMap) {
        var totalErrors = 0;
        var totalWarnings = 0;
        var accordionHtml = '';
        
        // Itera sobre os resultados para construir o HTML do acordeão
        for (var sectionSlug in results) {
            // Verifica se a seção existe no mapa antes de processar
            if (!sectionsMap.hasOwnProperty(sectionSlug)) {
                continue; 
            }

            var sectionResults = results[sectionSlug];
            var sectionTitle = sectionsMap[sectionSlug].title;
            var sectionContentHtml = '';
            var sectionErrors = 0;
            var sectionWarnings = 0;
            var headerIcon = '✅';
            var headerClass = 'status-good';

            // Constrói o conteúdo interno da seção (accordion-content)
            if (sectionResults && sectionResults.length > 0) {
                sectionResults.forEach(function(item) {
                    var icon = '';
                    switch(item.status) {
                        case 'good': icon = '✅'; break;
                        case 'warning': icon = '⚠️'; sectionWarnings++; break;
                        case 'error': icon = '❌'; sectionErrors++; break;
                        case 'info': icon = 'ℹ️'; break;
                    }
                    
                    sectionContentHtml += '<div class="scan-item">';
                    sectionContentHtml += '<span class="status-icon status-' + item.status + '">' + icon + '</span>';
                    
                    sectionContentHtml += '<div class="item-content">';
                    sectionContentHtml += '<strong>' + item.message + '</strong>';
                    
                    if (item.details) {
                        sectionContentHtml += '<div class="item-details">' + item.details + '</div>';
                    }

                    // Requisito: Apenas mostrar a recomendação se não for 'good'
                    if (item.recommendation && item.status !== 'good') {
                        sectionContentHtml += '<div class="recommendation">' + item.recommendation + '</div>';
                    }
                    sectionContentHtml += '</div>'; // Fim item-content
                    sectionContentHtml += '</div>'; // Fim scan-item
                });

                // Determina o status geral da seção para o cabeçalho
                if (sectionErrors > 0) {
                    headerIcon = '❌';
                    headerClass = 'status-error';
                    totalErrors += sectionErrors;
                } else if (sectionWarnings > 0) {
                    headerIcon = '⚠️';
                    headerClass = 'status-warning';
                    totalWarnings += sectionWarnings;
                }

            } else {
                 sectionContentHtml = '<div class="notice notice-success"><p>✅ Não foram encontrados problemas nesta seção.</p></div>';
            }

            // Constrói o item completo do acordeão
            accordionHtml += '<div class="accordion-item" data-status="' + headerClass + '">';
            accordionHtml += '<div class="accordion-header" id="header-' + sectionSlug + '">';
            accordionHtml += '<div class="header-title-wrapper">';
            accordionHtml += '<span class="header-icon ' + headerClass + '">' + headerIcon + '</span>';
            accordionHtml += '<span>' + sectionTitle + '</span>';
            accordionHtml += '</div>';
            accordionHtml += '<span class="toggle-arrow dashicons dashicons-arrow-down-alt2"></span>';
            accordionHtml += '</div>';
            accordionHtml += '<div class="accordion-content">'; 
            accordionHtml += sectionContentHtml;
            accordionHtml += '</div>';
            accordionHtml += '</div>';
        }

        // 2. Injeta o HTML e exibe o wrapper
        var $accordionWrapper = $('#results-accordion-wrapper');
        $accordionWrapper.html(accordionHtml).show();

        // 3. Exibe a mensagem de resumo global
        if (totalErrors > 0) {
            $('#scan-results').html('<div class="notice notice-error"><p>❌ **Verificação Crítica!** Encontramos ' + totalErrors + ' problemas de segurança críticos e ' + totalWarnings + ' avisos. Expanda as seções marcadas em vermelho para revisar e blindar seu site.</p></div>');
        } else if (totalWarnings > 0) {
            $('#scan-results').html('<div class="notice notice-warning"><p>⚠️ **Verificação Concluída.** Não há erros críticos, mas encontramos ' + totalWarnings + ' avisos de otimização/segurança. Considere seguir as recomendações para blindagem total.</p></div>');
        } else {
            $('#scan-results').html('<div class="notice notice-success"><p>🎉 **Parabéns!** O scanner não encontrou problemas de segurança ou desempenho urgentes. Seu site está bem blindado!</p></div>');
        }
    }
});